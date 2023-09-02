package login_test

// 步骤 187：管理员强制下线页面契约测试（页面层 + 受控后端替身）。
// 真实 session.Service / authz / 审计集成见 serverapp 阶段测试与领域测试。

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

const adminSessionsTestUserID = "usr_00000000000000000000000000000001"
const adminSessionsTestTargetID = "usr_00000000000000000000000000000002"

// fakeAdminSessionsBackend 是页面后端替身，只验证页面契约与错误映射。
type fakeAdminSessionsBackend struct {
	caps         login.UIAdminSessionsCapabilities
	page         login.UIAdminSessionPage
	listErr      error
	revokeErr    error
	revoked      int64
	lastAction   login.UIAdminSessionRevokeAction
	lastEvidence login.UIAdminSessionEvidence
	listCalls    int
	revokeCalls  int
}

func (f *fakeAdminSessionsBackend) Capabilities(context.Context, *http.Request,
	string) (login.UIAdminSessionsCapabilities, error) {
	return f.caps, nil
}

func (f *fakeAdminSessionsBackend) ListSessions(_ context.Context, _ *http.Request, _ string,
	_ login.UIAdminSessionQuery) (login.UIAdminSessionPage, error) {
	f.listCalls++
	if f.listErr != nil {
		return login.UIAdminSessionPage{}, f.listErr
	}
	return f.page, nil
}

func (f *fakeAdminSessionsBackend) RevokeSessions(_ context.Context, _ *http.Request, _ string,
	action login.UIAdminSessionRevokeAction,
	evidence login.UIAdminSessionEvidence) (login.UIAdminSessionRevokeResult, error) {
	f.revokeCalls++
	f.lastAction = action
	f.lastEvidence = evidence
	if f.revokeErr != nil {
		return login.UIAdminSessionRevokeResult{}, f.revokeErr
	}
	return login.UIAdminSessionRevokeResult{Revoked: f.revoked, ScopeAppID: action.ScopeAppID}, nil
}

// newAdminSessionsTestUI 构造仅注册管理员会话页的最小 WebUI。
func newAdminSessionsTestUI(t *testing.T, backend login.UIAdminSessionsBackend,
	reauth func(context.Context, string,
		login.UIAdminSessionActionBinding) (login.UIAdminSessionEvidence, error)) *login.WebUI {
	t.Helper()
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: appsTestSessions{userID: adminSessionsTestUserID, management: true},
		PageAdminSessions: &login.UIPageAdminSessionsOptions{
			Backend: backend, Reauth: reauth,
		},
	})
	if err != nil {
		t.Fatalf("页面框架: %v", err)
	}
	return ui
}

// serveAdminSessionsPage 发起 GET/POST 页面请求。
func serveAdminSessionsPage(ui http.Handler, method, target string,
	form url.Values) *httptest.ResponseRecorder {
	var body *bytes.Reader
	if method == http.MethodPost {
		body = bytes.NewReader([]byte(form.Encode()))
	} else {
		body = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, "http://example.test"+target, body)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// TestAdminSessionsPageRoutesAndValidation 验证路由集合、依赖校验与查询/撤销渲染。
func TestAdminSessionsPageRoutesAndValidation(t *testing.T) {
	if _, err := login.NewWebUI(login.WebUIOptions{
		Session:           appsTestSessions{userID: adminSessionsTestUserID, management: true},
		PageAdminSessions: &login.UIPageAdminSessionsOptions{},
	}); err == nil {
		t.Fatal("缺少后端适配器时页面应构造失败")
	}
	backend := &fakeAdminSessionsBackend{
		caps: login.UIAdminSessionsCapabilities{List: true, Revoke: true},
		page: login.UIAdminSessionPage{
			TargetUserID: adminSessionsTestTargetID, Page: 1, PageSize: 20, Total: 1,
			Sessions: []login.UIAdminSessionView{{
				ID: "ses_00000000000000000000000000000003", Kind: "normal",
				CreatedAt: time.Now(), LastSeenAt: time.Now(),
				AbsoluteExpiresAt: time.Now().Add(time.Hour),
				ClientUserAgent:   "cli/1.0",
			}},
		},
		revoked: 1,
	}
	ui := newAdminSessionsTestUI(t, backend,
		func(context.Context, string,
			login.UIAdminSessionActionBinding) (login.UIAdminSessionEvidence, error) {
			return login.UIAdminSessionEvidence{VerifiedAt: time.Now(), Strength: "strong",
				Complete: true, Confirmed: true}, nil
		})
	routes := map[string]bool{}
	for _, route := range ui.Routes() {
		routes[route.Name] = true
	}
	for _, name := range []string{"admin.sessions", "admin.sessions.revoke"} {
		if !routes[name] {
			t.Fatalf("缺少路由 %s", name)
		}
	}

	// 未填写目标用户：只显示查询表单，不查询任何用户会话。
	formOnly := serveAdminSessionsPage(ui, http.MethodGet, "/admin/sessions", nil)
	if formOnly.Code != http.StatusOK || backend.listCalls != 0 {
		t.Fatalf("未填写目标时不应查询: code=%d calls=%d", formOnly.Code, backend.listCalls)
	}
	body := formOnly.Body.String()
	if strings.Contains(body, "ses_00000000000000000000000000000003") {
		t.Fatalf("未查询时不应显示会话: %s", body)
	}

	// 填写目标用户：渲染会话列表与撤销表单（含目标/范围/影响说明）。
	filled := serveAdminSessionsPage(ui, http.MethodGet,
		"/admin/sessions?target_user_id="+adminSessionsTestTargetID, nil)
	if filled.Code != http.StatusOK || backend.listCalls != 1 {
		t.Fatalf("查询应成功: code=%d calls=%d", filled.Code, backend.listCalls)
	}
	body = filled.Body.String()
	for _, want := range []string{"ses_00000000000000000000000000000003", "强制下线",
		"OAuth", "会话秘密"} {
		if !strings.Contains(body, want) {
			t.Fatalf("页面缺少 %q: %s", want, body)
		}
	}
}

// TestAdminSessionsPageRevokeFlow 验证确认/理由校验、再认证失败拒绝、成功与幂等提示。
func TestAdminSessionsPageRevokeFlow(t *testing.T) {
	backend := &fakeAdminSessionsBackend{
		caps:    login.UIAdminSessionsCapabilities{List: true, Revoke: true},
		page:    login.UIAdminSessionPage{TargetUserID: adminSessionsTestTargetID},
		revoked: 2,
	}
	reauthCalls := 0
	ui := newAdminSessionsTestUI(t, backend,
		func(context.Context, string,
			login.UIAdminSessionActionBinding) (login.UIAdminSessionEvidence, error) {
			reauthCalls++
			return login.UIAdminSessionEvidence{VerifiedAt: time.Now(), Strength: "strong",
				Complete: true, Confirmed: true}, nil
		})
	validForm := url.Values{
		"mode": {"user"}, "target_user_id": {adminSessionsTestTargetID},
		"reason": {"security incident response"}, "confirm": {"yes"},
	}

	// 缺少确认/理由：400，不调用再次认证与撤销。
	for _, bad := range []url.Values{
		{"mode": {"user"}, "target_user_id": {adminSessionsTestTargetID}, "reason": {"x"}},
		{"mode": {"user"}, "target_user_id": {adminSessionsTestTargetID}, "confirm": {"yes"}},
		{"mode": {"bad"}, "target_user_id": {adminSessionsTestTargetID}, "reason": {"x"}, "confirm": {"yes"}},
	} {
		reply := serveAdminSessionsPage(ui, http.MethodPost, "/admin/sessions/revoke", bad)
		if reply.Code != http.StatusBadRequest {
			t.Fatalf("非法表单应 400，实际 %d: %s", reply.Code, reply.Body.String())
		}
	}
	if reauthCalls != 0 || backend.revokeCalls != 0 {
		t.Fatalf("非法表单不应调用再认证/撤销: reauth=%d revoke=%d", reauthCalls, backend.revokeCalls)
	}

	// 再次认证失败：403 且不撤销。
	failingUI := newAdminSessionsTestUI(t, backend,
		func(context.Context, string,
			login.UIAdminSessionActionBinding) (login.UIAdminSessionEvidence, error) {
			return login.UIAdminSessionEvidence{}, context.Canceled
		})
	reply := serveAdminSessionsPage(failingUI, http.MethodPost, "/admin/sessions/revoke", validForm)
	if reply.Code != http.StatusForbidden || backend.revokeCalls != 0 {
		t.Fatalf("再认证失败应 403 且不撤销: code=%d revoke=%d", reply.Code, backend.revokeCalls)
	}

	// 成功：真实撤销数展示；动作/证据传给后端。
	reply = serveAdminSessionsPage(ui, http.MethodPost, "/admin/sessions/revoke", validForm)
	if reply.Code != http.StatusOK || backend.revokeCalls != 1 {
		t.Fatalf("撤销应成功: code=%d calls=%d body=%s", reply.Code, backend.revokeCalls, reply.Body.String())
	}
	if backend.lastAction.TargetUserID != adminSessionsTestTargetID ||
		backend.lastAction.Reason != "security incident response" || !backend.lastAction.Confirm {
		t.Fatalf("撤销动作参数不符: %+v", backend.lastAction)
	}
	if !backend.lastEvidence.Complete || !backend.lastEvidence.Confirmed ||
		backend.lastEvidence.Strength != "strong" {
		t.Fatalf("页面证据不符: %+v", backend.lastEvidence)
	}
	if body := reply.Body.String(); !strings.Contains(body, "已撤销活动会话数") {
		t.Fatalf("成功页缺少撤销数: %s", body)
	}

	// 幂等 0：明确显示“不代表发生了撤销”。
	backend.revoked = 0
	reply = serveAdminSessionsPage(ui, http.MethodPost, "/admin/sessions/revoke", validForm)
	if body := reply.Body.String(); !strings.Contains(body, "不代表发生了撤销") {
		t.Fatalf("0 撤销页缺少幂等说明: %s", body)
	}
}

// TestAdminSessionsPageCapabilities 验证无撤销能力时不渲染可提交表单。
func TestAdminSessionsPageCapabilities(t *testing.T) {
	backend := &fakeAdminSessionsBackend{
		caps: login.UIAdminSessionsCapabilities{List: false, Revoke: false},
	}
	ui := newAdminSessionsTestUI(t, backend,
		func(context.Context, string,
			login.UIAdminSessionActionBinding) (login.UIAdminSessionEvidence, error) {
			return login.UIAdminSessionEvidence{}, context.Canceled
		})
	reply := serveAdminSessionsPage(ui, http.MethodGet, "/admin/sessions", nil)
	if reply.Code != http.StatusForbidden {
		t.Fatalf("无查询能力应 403，实际 %d", reply.Code)
	}
	if strings.Contains(reply.Body.String(), `name="mode"`) {
		t.Fatalf("无撤销能力时不应渲染撤销表单: %s", reply.Body.String())
	}
}
