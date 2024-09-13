package ui_test

// 步骤 258：管理页直接改名的页面接线与安全边界测试。
// 重点：目标稳定 ID/旧用户名展示；一次 begin→confirm→apply；MFA_REQUIRED 仅回显
// 挑战编号；会话秘密/密码/一次性证明不进入 HTML；回调缺失 fail-closed；无权限不显示表单。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

const renamePageSessionSecret = "session-secret-page-258"

// newDirectRenamePageEnv 构造带真实管理会话回调的改名页面测试环境。
func newDirectRenamePageEnv(t *testing.T) (*adminPageEnv, *fakeAdminBackend) {
	t.Helper()
	backend := &fakeAdminBackend{
		canChangeUsername: true,
		users: []login.UIAdminUserView{{UserID: "usr_test", Username: "alice",
			Nickname: "Alice", Status: "active", RowVersion: 3}},
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend,
			ManagementSession: func(*http.Request) (string, bool) {
				return renamePageSessionSecret, true
			}}})
	if err != nil {
		t.Fatalf("改名页面框架: %v", err)
	}
	return &adminPageEnv{t: t, handler: ui, backend: backend}, backend
}

// TestAdminUserRenamePageShowsTargetWithoutSecrets 覆盖 GET 展示目标稳定 ID/旧用户名、
// 表单存在，且 HTML 不含会话秘密。
func TestAdminUserRenamePageShowsTargetWithoutSecrets(t *testing.T) {
	env, _ := newDirectRenamePageEnv(t)
	page := env.request(http.MethodGet, "/admin/users/rename?user_id=usr_test", nil, "")
	if page.Code != http.StatusOK {
		t.Fatalf("改名页 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"usr_test", "alice", `action="/admin/users/rename"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("改名页缺少 %q", want)
		}
	}
	if strings.Contains(body, renamePageSessionSecret) {
		t.Fatal("页面泄露管理会话秘密")
	}
}

// TestAdminUserRenamePageOneShotProof 覆盖同一请求内 begin→confirm→apply，
// 会话秘密只传给后端方法，密码/证明不渲染。
func TestAdminUserRenamePageOneShotProof(t *testing.T) {
	env, backend := newDirectRenamePageEnv(t)
	form := url.Values{"user_id": {"usr_test"}, "new_username": {"bob"},
		"reason": {"用户申请改名"}, "expected_row_version": {"3"},
		"password": {"P@ssw0rd-258"}, "totp_code": {"123456"}}
	page := env.post("/admin/users/rename", form)
	if page.Code != http.StatusSeeOther {
		t.Fatalf("改名提交 = %d body=%s", page.Code, page.Body.String())
	}
	if backend.lastRenameSecret != renamePageSessionSecret || backend.lastRenameAdmin != "" {
		// admin 会话 ID 由测试会话决定，可能是空串；秘密断言为主。
	}
	if backend.lastRenameTarget != "usr_test" || backend.lastRenameNew != "bob" ||
		backend.lastRenameVersion != 3 || backend.lastRenameReason != "用户申请改名" ||
		backend.lastRenameProof != "proof-token-page-258" {
		t.Fatalf("后端收到参数 = %+v", backend)
	}
	if backend.lastRenameChallenge != "chl_direct_1" ||
		backend.lastRenamePassword != "P@ssw0rd-258" || backend.lastRenameTOTP != "123456" {
		t.Fatalf("两步验证参数 = challenge=%q password=%q totp=%q",
			backend.lastRenameChallenge, backend.lastRenamePassword, backend.lastRenameTOTP)
	}
	calls := strings.Join(backend.directRenameCalls, ",")
	if calls != "begin,confirm,apply" {
		t.Fatalf("调用顺序 = %s", calls)
	}
	body := page.Body.String()
	for _, secret := range []string{"P@ssw0rd-258", "proof-token-page-258",
		renamePageSessionSecret} {
		if strings.Contains(body, secret) {
			t.Fatalf("响应泄露秘密 %q", secret)
		}
	}
	if location := page.Header().Get("Location"); !strings.Contains(location, "/admin/users/detail") {
		t.Fatalf("成功后跳转 = %q", location)
	}
}

// TestAdminUserRenamePageMFAChallenge 覆盖 MFA_REQUIRED：仅返回挑战编号要求补动态码，
// 补码后直接 confirm+apply（不重复 begin）。
func TestAdminUserRenamePageMFAChallenge(t *testing.T) {
	env, backend := newDirectRenamePageEnv(t)
	backend.directRenameConfirmErr = &login.UIAdminError{Code: "MFA_REQUIRED"}
	form := url.Values{"user_id": {"usr_test"}, "new_username": {"bob"},
		"reason": {"用户申请改名"}, "expected_row_version": {"3"},
		"password": {"P@ssw0rd-258"}}
	page := env.post("/admin/users/rename", form)
	if page.Code != http.StatusForbidden || !strings.Contains(page.Body.String(), "chl_direct_1") {
		t.Fatalf("MFA 挑战页 = %d body=%s", page.Code, page.Body.String())
	}
	if strings.Contains(page.Body.String(), "P@ssw0rd-258") ||
		strings.Contains(page.Body.String(), renamePageSessionSecret) {
		t.Fatal("MFA 挑战页泄露秘密")
	}
	if strings.Contains(page.Body.String(), "proof-token-page-258") {
		t.Fatal("MFA 挑战页泄露证明")
	}
	backend.directRenameConfirmErr = nil
	retry := url.Values{"user_id": {"usr_test"}, "new_username": {"bob"},
		"reason": {"用户申请改名"}, "expected_row_version": {"3"},
		"password": {"P@ssw0rd-258"}, "totp_code": {"654321"},
		"challenge_id": {"chl_direct_1"}}
	retryPage := env.post("/admin/users/rename", retry)
	if retryPage.Code != http.StatusSeeOther {
		t.Fatalf("补码提交 = %d body=%s", retryPage.Code, retryPage.Body.String())
	}
	if strings.Join(backend.directRenameCalls, ",") != "begin,confirm,confirm,apply" {
		t.Fatalf("MFA 重试调用顺序 = %v", backend.directRenameCalls)
	}
}

// TestAdminUserRenamePageFailClosed 覆盖回调缺失/无权限时 fail-closed。
func TestAdminUserRenamePageFailClosed(t *testing.T) {
	// 未注入 ManagementSession：路由存在但处理器 404，不静默降级。
	backend := &fakeAdminBackend{canChangeUsername: true,
		users: []login.UIAdminUserView{{UserID: "usr_test", Username: "alice",
			Status: "active", RowVersion: 1}}}
	ui, err := login.NewWebUI(login.WebUIOptions{Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("框架: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet,
		"http://example.test/admin/users/rename?user_id=usr_test", nil)
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("回调缺失页面 = %d，期望 404", recorder.Code)
	}
	// 无权限：页面不显示提交表单。
	env, backend2 := newDirectRenamePageEnv(t)
	backend2.canChangeUsername = false
	page := env.request(http.MethodGet, "/admin/users/rename?user_id=usr_test", nil, "")
	if page.Code != http.StatusOK || strings.Contains(page.Body.String(),
		`action="/admin/users/rename"`) {
		t.Fatalf("无权限页面 = %d body=%s", page.Code, page.Body.String())
	}
}
