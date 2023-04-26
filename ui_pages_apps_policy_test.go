package login_test

// 步骤 146 页面契约测试：真实 WebUI 路由/handler + 受控应用后端替身，验证策略
// 读取、可写表单、一次性 reauth 绑定、行版本冲突和越权/非法表单拒绝。真实
// SQLite/managedapi 集成测试见 internal/serverapp 与 internal/managedapi。

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// appsPolicyPageBackend 在既有 fakeAppsBackend 上实现可选 UIAppsPolicyBackend。
type appsPolicyPageBackend struct {
	*fakeAppsBackend
	setCalls   int
	lastChange login.UIAppPolicyChange
	lastDigest string
	lastRow    int64
	lastAppID  string
	writeErr   error
}

func (b *appsPolicyPageBackend) SetManagedPolicy(_ context.Context, _, appID string,
	change login.UIAppPolicyChange, expectedRowVersion int64, _ string,
	policyDigest string) (login.UIAppPolicyView, error) {
	b.setCalls++
	b.lastChange = change
	b.lastDigest = policyDigest
	b.lastRow = expectedRowVersion
	b.lastAppID = appID
	if b.writeErr != nil {
		return login.UIAppPolicyView{}, b.writeErr
	}
	if expectedRowVersion != b.policy.RowVersion {
		return login.UIAppPolicyView{}, &login.UIAppsError{Code: "CONFLICT"}
	}
	view := b.policy
	view.RowVersion = expectedRowVersion + 1
	view.Allowed = nil
	for _, id := range change.Allowed {
		view.Allowed = append(view.Allowed, login.UIAppPolicyOperation{ID: id})
	}
	return view, nil
}

func newAppsPolicyTestUI(t *testing.T, backend *appsPolicyPageBackend,
	reauth func(context.Context, string, login.UIAppPolicyActionBinding) error) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: appsTestSessions{userID: "usr_admin", management: true},
		PageApps: &login.UIPageAppsOptions{
			Backend: backend, PolicyBackend: backend, PolicyReauth: reauth,
		},
	})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

func appsPolicyTestBackend() *appsPolicyPageBackend {
	backend := &appsPolicyPageBackend{fakeAppsBackend: newAppsFakeBackend()}
	backend.policy = login.UIAppPolicyView{
		State: "policy", ApplicationID: appsTestAppID, RowVersion: 4,
		UpdatedBy: "sys-policy-reader", CanWrite: true,
		Allowed: []login.UIAppPolicyOperation{{ID: "members.list", Object: "member"}},
		Objects: []login.UIAppPolicyObject{{Object: "member", Mode: "all"}},
		Fields: []login.UIAppPolicyFields{{Object: "member",
			Read: []string{"display_name"}, Write: []string{"display_name"}}},
		Limits:  login.UIAppPolicyLimits{MaxLimit: 20, MaxOffset: 100000, MaxBatch: 10},
		Catalog: []login.UIAppPolicyOperationCatalog{{ID: "members.list", Object: "member", Description: "查询应用成员列表"}},
	}
	return backend
}

func appsPolicyForm() url.Values {
	return url.Values{
		"csrf_token": {"token"}, "app_id": {appsTestAppID}, "row_version": {"4"},
		"policy_ops": {"members.list"}, "policy_service_ops": {""},
		"policy_objects":   {"member|all|"},
		"policy_fields":    {"member|display_name|display_name"},
		"policy_max_limit": {"20"}, "policy_max_offset": {"100000"},
		"policy_max_batch": {"10"},
	}
}

func TestUIPageAppsGrantsWriteFlow(t *testing.T) {
	backend := appsPolicyTestBackend()
	var bound login.UIAppPolicyActionBinding
	ui := newAppsPolicyTestUI(t, backend,
		func(_ context.Context, userID string, binding login.UIAppPolicyActionBinding) error {
			if userID != "usr_admin" {
				t.Fatalf("reauth user = %q", userID)
			}
			bound = binding
			return nil
		})
	get := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/grants?app_id="+appsTestAppID, nil)
	if get.Code != 200 || !strings.Contains(get.Body.String(), "编辑托管管理 API 委托策略") ||
		!strings.Contains(get.Body.String(), "members.list") {
		t.Fatalf("可写许可页渲染 = %d", get.Code)
	}
	post := serveAppsPage(ui, http.MethodPost,
		"/admin/applications/grants", appsPolicyForm())
	if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "策略已保存") {
		t.Fatalf("策略保存状态 = %d body=%.2000s", post.Code, post.Body.String())
	}
	if backend.setCalls != 1 || backend.lastAppID != appsTestAppID ||
		backend.lastRow != 4 || backend.lastDigest == "" ||
		bound.ApplicationID != appsTestAppID || bound.ExpectedRowVersion != 4 ||
		bound.PolicyDigest != backend.lastDigest || bound.RequestID == "" {
		t.Fatalf("保存绑定异常: calls=%d app=%q row=%d digest=%q bound=%+v",
			backend.setCalls, backend.lastAppID, backend.lastRow, backend.lastDigest, bound)
	}
	if backend.lastChange.Digest() != backend.lastDigest {
		t.Fatalf("提交摘要与 reauth 绑定不一致")
	}
}

func TestUIPageAppsGrantsRejectsBadInputs(t *testing.T) {
	backend := appsPolicyTestBackend()
	reauthCalls := 0
	ui := newAppsPolicyTestUI(t, backend,
		func(context.Context, string, login.UIAppPolicyActionBinding) error {
			reauthCalls++
			return errors.New("重新验证失败")
		})
	// reauth 失败必须在策略写入前返回，且不能调用后端。
	form := appsPolicyForm()
	denied := serveAppsPage(ui, http.MethodPost, "/admin/applications/grants", form)
	if denied.Code != http.StatusForbidden || backend.setCalls != 0 ||
		!strings.Contains(denied.Body.String(), "重新完成强认证") {
		t.Fatalf("reauth 失败路径 = %d writes=%d", denied.Code, backend.setCalls)
	}
	// 未知字段/非法对象模式由 handler 在白名单/解析阶段拒绝。
	unknown := appsPolicyForm()
	unknown.Set("unexpected", "x")
	if got := serveAppsPage(ui, http.MethodPost,
		"/admin/applications/grants", unknown).Code; got != http.StatusBadRequest {
		t.Fatalf("未知字段状态 = %d", got)
	}
	invalidMode := appsPolicyForm()
	invalidMode.Set("policy_objects", "member|system|")
	if got := serveAppsPage(ui, http.MethodPost,
		"/admin/applications/grants", invalidMode).Code; got != http.StatusBadRequest {
		t.Fatalf("非法对象范围状态 = %d", got)
	}
	_ = reauthCalls
}

func TestUIPageAppsGrantsVersionConflict(t *testing.T) {
	backend := appsPolicyTestBackend()
	ui := newAppsPolicyTestUI(t, backend,
		func(context.Context, string, login.UIAppPolicyActionBinding) error { return nil })
	form := appsPolicyForm()
	form.Set("row_version", "3") // 旧版本：后端返回 CONFLICT
	conflict := serveAppsPage(ui, http.MethodPost, "/admin/applications/grants", form)
	if conflict.Code != http.StatusConflict ||
		!strings.Contains(conflict.Body.String(), "已变化") {
		t.Fatalf("版本冲突 = %d body=%.2000s", conflict.Code, conflict.Body.String())
	}
}

func TestUIPageAppsGrantsReadOnlyWithoutPolicyBackend(t *testing.T) {
	backend := newAppsFakeBackend()
	backend.policy = login.UIAppPolicyView{State: "policy", ApplicationID: appsTestAppID,
		RowVersion: 4, UpdatedBy: "sys"}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session:  appsTestSessions{userID: "usr_admin", management: true},
		PageApps: &login.UIPageAppsOptions{Backend: backend},
	})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	page := serveAppsPage(ui, http.MethodGet,
		"/admin/applications/grants?app_id="+appsTestAppID, nil)
	if page.Code != 200 || strings.Contains(page.Body.String(), "编辑托管管理 API 委托策略") {
		t.Fatalf("无策略后端时不应出现可写表单 = %d", page.Code)
	}
}
