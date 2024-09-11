package ui_test

// 步骤 266：通用后台任务页测试。
//   - 宿主提供 UIAdminTasksBackend 时注册 /admin/tasks 并渲染任务元数据；
//   - 只展示白名单字段（无任务载荷/秘密），分页游标来自后端真实结果；
//   - 未装配后端时不注册路由（404）；非法筛选值 400，不静默当作全部。

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// fakeTasksBackend 复用 fakeAdminBackend 的其余接口，只实现任务列表读取。
type fakeTasksBackend struct {
	*fakeAdminBackend
	page  login.UIAdminTaskPage
	fail  bool
	query login.UIAdminTaskQuery
}

func (f *fakeTasksBackend) ListTasks(_ context.Context, adminID string,
	query login.UIAdminTaskQuery) (login.UIAdminTaskPage, error) {
	f.query = query
	if f.fail {
		return login.UIAdminTaskPage{}, &login.UIAdminError{Code: "ACCESS_DENIED"}
	}
	return f.page, nil
}

// TestAdminTasksPageRendersBoundedList 验证任务页注册、渲染与分页游标。
func TestAdminTasksPageRendersBoundedList(t *testing.T) {
	backend := &fakeTasksBackend{fakeAdminBackend: &fakeAdminBackend{},
		page: login.UIAdminTaskPage{
			Limit: 2, HasMore: true, NextCursor: "next-opaque-cursor",
			Tasks: []login.UIAdminTask{
				{ID: "job_task_page_0001", Kind: "user.batch.export",
					State: "running", InitiatorType: "user",
					InitiatorID: "usr_00000000000000000000000000000001",
					Attempt:     1, MaxAttempts: 2,
					CreatedAt: time.Date(2026, 11, 26, 1, 0, 0, 0, time.UTC),
					UpdatedAt: time.Date(2026, 11, 26, 1, 1, 0, 0, time.UTC)},
				{ID: "job_task_page_0002", Kind: "audit.export", State: "failed",
					ErrorCode: "TASK_FAILED", Attempt: 2, MaxAttempts: 2},
			}}}
	webUI, err := login.NewWebUI(login.WebUIOptions{
		Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend,
			Tasks: &login.UIPageAdminTasksOptions{Backend: backend}},
	})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	recorder := httptestRequest(t, webUI, http.MethodGet,
		"http://example.test/admin/tasks?state=running&kind=user.batch", nil, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("任务页状态 = %d，body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{"后台任务", "job_task_page_0001", "user.batch.export",
		"running", "job_task_page_0002", "failed", "TASK_FAILED",
		"next-opaque-cursor", "取消任务", "取消邮件投递"} {
		if !strings.Contains(body, want) {
			t.Fatalf("任务页缺少 %q: %s", want, body)
		}
	}
	if backend.query.State != "running" || backend.query.Kind != "user.batch" {
		t.Fatalf("筛选未传给后端: %+v", backend.query)
	}
	// 页面不得包含任务载荷/秘密字段。
	for _, forbidden := range []string{"payload", "sealed", "password", "token="} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("任务页出现疑似载荷/秘密 %q", forbidden)
		}
	}
}

// TestAdminTasksPageAbsentWithoutBackend 验证未装配后端时不注册路由。
func TestAdminTasksPageAbsentWithoutBackend(t *testing.T) {
	backend := &fakeAdminBackend{}
	webUI, err := login.NewWebUI(login.WebUIOptions{
		Session:   adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend},
	})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	recorder := httptestRequest(t, webUI, http.MethodGet,
		"http://example.test/admin/tasks", nil, "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("未装配任务后端时状态 = %d，期望 404", recorder.Code)
	}
}

// TestAdminTasksPageRejectsInvalidFilter 验证非法状态/类型筛选被拒绝（不当作全部）。
func TestAdminTasksPageRejectsInvalidFilter(t *testing.T) {
	backend := &fakeTasksBackend{fakeAdminBackend: &fakeAdminBackend{}}
	webUI, err := login.NewWebUI(login.WebUIOptions{
		Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend,
			Tasks: &login.UIPageAdminTasksOptions{Backend: backend}},
	})
	if err != nil {
		t.Fatalf("管理页框架: %v", err)
	}
	for _, target := range []string{
		"http://example.test/admin/tasks?state=not-a-state",
		"http://example.test/admin/tasks?kind=" + strings.Repeat("a", 65),
		"http://example.test/admin/tasks?limit=101",
	} {
		recorder := httptestRequest(t, webUI, http.MethodGet, target, nil, "")
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s 状态 = %d，期望 400", target, recorder.Code)
		}
	}
}
