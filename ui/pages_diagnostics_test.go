package ui_test

// 步骤 233：管理页“运行诊断”入口测试。
//   - 宿主提供 UIAdminDiagnosticsBackend 时注册 /admin/diagnostics 并渲染脱敏视图；
//   - 未提供时不注册路由（404），不会占位成功或匿名可读；
//   - 页面数据只来自后端白名单视图，不拼接数据库/秘密。

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// fakeDiagnosticsBackend 复用 fakeAdminBackend 的其余接口，只实现诊断读取。
type fakeDiagnosticsBackend struct {
	*fakeAdminBackend
	view login.UIAdminDiagnosticsView
	fail bool
}

func (f *fakeDiagnosticsBackend) GetDiagnostics(_ context.Context, adminID,
	errorRequestID string) (login.UIAdminDiagnosticsView, error) {
	if f.fail {
		return login.UIAdminDiagnosticsView{}, &login.UIAdminError{Code: "ACCESS_DENIED"}
	}
	view := f.view
	view.ErrorRequestID = errorRequestID
	return view, nil
}

// TestAdminDiagnosticsPageRendersRedactedView 验证诊断页面注册与渲染。
func TestAdminDiagnosticsPageRendersRedactedView(t *testing.T) {
	backend := &fakeDiagnosticsBackend{fakeAdminBackend: &fakeAdminBackend{},
		view: login.UIAdminDiagnosticsView{
			GeneratedAt: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC),
			Status:      "ok", State: "running", Version: "test-version",
			ScopeID: "system", StorageStatus: "ok", StorageLatencyMS: 3,
			QueueCounts: []login.UIAdminDiagnosticsQueueCount{
				{Kind: "job", State: "queued", Count: 2},
				{Kind: "mail", State: "failed", Count: 1}},
			FeatureFlags: []login.UIAdminDiagnosticsFlag{
				{Name: "mail_enabled", Enabled: true}},
			PendingRestartStatus: "none",
		}}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend,
			Diagnostics: &login.UIPageAdminDiagnosticsOptions{Backend: backend}},
	})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	recorder := httptestRequest(t, ui, http.MethodGet,
		"http://example.test/admin/diagnostics?request_id=req_diag_page_1", nil, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("诊断页状态 = %d，body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{"运行诊断", "test-version", "queued", "mail_enabled",
		"req_diag_page_1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("诊断页缺少 %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"password", "smtp_password", "token=",
		"diag-secret", "DB_PATH"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("诊断页泄露 %q: %s", forbidden, body)
		}
	}
}

// TestAdminDiagnosticsPageAbsentWithoutBackend 验证未装配诊断后端时不注册路由。
func TestAdminDiagnosticsPageAbsentWithoutBackend(t *testing.T) {
	backend := &fakeAdminBackend{}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:   adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend},
	})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	recorder := httptestRequest(t, ui, http.MethodGet,
		"http://example.test/admin/diagnostics", nil, "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("未装配诊断后端时状态 = %d，期望 404", recorder.Code)
	}
}

// TestAdminDiagnosticsPageErrorDenied 验证后端拒绝时的受控错误页（无数据泄露）。
func TestAdminDiagnosticsPageErrorDenied(t *testing.T) {
	backend := &fakeDiagnosticsBackend{fakeAdminBackend: &fakeAdminBackend{}, fail: true}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend,
			Diagnostics: &login.UIPageAdminDiagnosticsOptions{Backend: backend}},
	})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	recorder := httptestRequest(t, ui, http.MethodGet,
		"http://example.test/admin/diagnostics", nil, "")
	if recorder.Code != http.StatusForbidden && recorder.Code != http.StatusUnauthorized {
		t.Fatalf("拒绝时状态 = %d，期望 401/403", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "diag-secret") {
		t.Fatalf("拒绝页泄露秘密")
	}
}

// httptestRequest 构造一次页面请求。
func httptestRequest(t *testing.T, handler http.Handler, method, target string,
	body []byte, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
