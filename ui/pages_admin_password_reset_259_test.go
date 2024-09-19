package ui_test

// 步骤 259：管理页直接重置密码的页面接线与安全边界测试。
// 重点：目标稳定 ID 展示；一次 begin→confirm→apply；MFA_REQUIRED 仅回显挑战编号；
// 新密码/管理密码/一次性证明不进入 HTML；回调/权限缺失 fail-closed；两次口令不一致拒绝。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

const passwordResetPageSecret = "session-secret-reset-259"

// newPasswordResetPageEnv 构造带会话回调与重置后端的页面测试环境。
func newPasswordResetPageEnv(t *testing.T) (*adminPageEnv, *fakeAdminBackend) {
	t.Helper()
	backend := &fakeAdminBackend{
		canResetPassword: true,
		users: []login.UIAdminUserView{{UserID: "usr_reset", Username: "alice",
			Status: "active", RowVersion: 2}},
	}
	ui, err := login.NewWebUI(login.WebUIOptions{
		Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend,
			DirectPasswordReset: backend,
			ManagementSession: func(*http.Request) (string, bool) {
				return passwordResetPageSecret, true
			}}})
	if err != nil {
		t.Fatalf("重置密码页面框架: %v", err)
	}
	return &adminPageEnv{t: t, handler: ui, backend: backend}, backend
}

// TestAdminPasswordResetPageShowsTargetWithoutSecrets 覆盖 GET 展示与不泄露秘密。
func TestAdminPasswordResetPageShowsTargetWithoutSecrets(t *testing.T) {
	env, _ := newPasswordResetPageEnv(t)
	page := env.request(http.MethodGet, "/admin/users/password-reset?user_id=usr_reset", nil, "")
	if page.Code != http.StatusOK {
		t.Fatalf("重置密码页 = %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"usr_reset", "alice", `action="/admin/users/password-reset"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("重置密码页缺少 %q", want)
		}
	}
	if strings.Contains(body, passwordResetPageSecret) {
		t.Fatal("页面泄露管理会话秘密")
	}
}

// TestAdminPasswordResetPageOneShotProof 覆盖一次两步验证后立即提交，秘密/证明不渲染。
func TestAdminPasswordResetPageOneShotProof(t *testing.T) {
	env, backend := newPasswordResetPageEnv(t)
	form := url.Values{"user_id": {"usr_reset"},
		"new_password": {"N3w!Passw0rd#259"}, "new_password_confirm": {"N3w!Passw0rd#259"},
		"reason": {"用户申请重置"}, "password": {"AdminP@ss1"}, "totp_code": {"123456"}}
	page := env.post("/admin/users/password-reset", form)
	if page.Code != http.StatusOK {
		t.Fatalf("重置提交 = %d body=%s", page.Code, page.Body.String())
	}
	if strings.Join(backend.directPasswordCalls, ",") != "begin,confirm,apply" {
		t.Fatalf("调用顺序 = %v", backend.directPasswordCalls)
	}
	if backend.lastResetSecret != passwordResetPageSecret ||
		backend.lastResetTarget != "usr_reset" ||
		backend.lastResetNewPassword != "N3w!Passw0rd#259" ||
		backend.lastResetReason != "用户申请重置" ||
		backend.lastResetProof != "proof-reset-page-259" ||
		backend.lastResetChallenge != "chl_reset_1" ||
		backend.lastResetAdminPassword != "AdminP@ss1" || backend.lastResetTOTP != "123456" {
		t.Fatalf("后端收到参数异常: %+v", backend)
	}
	body := page.Body.String()
	for _, secret := range []string{"N3w!Passw0rd#259", "proof-reset-page-259",
		"AdminP@ss1", passwordResetPageSecret} {
		if strings.Contains(body, secret) {
			t.Fatalf("响应泄露秘密 %q", secret)
		}
	}
	for _, want := range []string{"must_change", "security_version"} {
		_ = want
	}
	if !strings.Contains(body, "重置已完成") || !strings.Contains(body, ">3<") {
		t.Fatalf("成功结果缺少脱敏事实: %s", body)
	}
}

// TestAdminPasswordResetPageMFAChallenge 覆盖 MFA_REQUIRED：仅回显挑战编号，补码后提交。
func TestAdminPasswordResetPageMFAChallenge(t *testing.T) {
	env, backend := newPasswordResetPageEnv(t)
	backend.resetConfirmErr = &login.UIAdminError{Code: "MFA_REQUIRED"}
	form := url.Values{"user_id": {"usr_reset"},
		"new_password": {"N3w!Passw0rd#259"}, "new_password_confirm": {"N3w!Passw0rd#259"},
		"reason": {"用户申请重置"}, "password": {"AdminP@ss1"}}
	page := env.post("/admin/users/password-reset", form)
	if page.Code != http.StatusForbidden || !strings.Contains(page.Body.String(), "chl_reset_1") {
		t.Fatalf("MFA 挑战页 = %d body=%s", page.Code, page.Body.String())
	}
	if strings.Contains(page.Body.String(), "N3w!Passw0rd#259") ||
		strings.Contains(page.Body.String(), "AdminP@ss1") {
		t.Fatal("MFA 挑战页泄露秘密")
	}
	backend.resetConfirmErr = nil
	retry := url.Values{"user_id": {"usr_reset"},
		"new_password": {"N3w!Passw0rd#259"}, "new_password_confirm": {"N3w!Passw0rd#259"},
		"reason": {"用户申请重置"}, "password": {"AdminP@ss1"},
		"totp_code": {"654321"}, "challenge_id": {"chl_reset_1"}}
	retryPage := env.post("/admin/users/password-reset", retry)
	if retryPage.Code != http.StatusOK {
		t.Fatalf("补码提交 = %d body=%s", retryPage.Code, retryPage.Body.String())
	}
	if strings.Join(backend.directPasswordCalls, ",") != "begin,confirm,confirm,apply" {
		t.Fatalf("MFA 重试调用顺序 = %v", backend.directPasswordCalls)
	}
}

// TestAdminPasswordResetPageFailClosed 覆盖回调缺失/无权限/两次口令不一致。
func TestAdminPasswordResetPageFailClosed(t *testing.T) {
	backend := &fakeAdminBackend{canResetPassword: true,
		users: []login.UIAdminUserView{{UserID: "usr_reset", Username: "alice",
			Status: "active", RowVersion: 1}}}
	ui, err := login.NewWebUI(login.WebUIOptions{Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend,
			DirectPasswordReset: backend}})
	if err != nil {
		t.Fatalf("框架: %v", err)
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet,
		"http://example.test/admin/users/password-reset?user_id=usr_reset", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("回调缺失页面 = %d，期望 404", recorder.Code)
	}
	env, backend2 := newPasswordResetPageEnv(t)
	backend2.canResetPassword = false
	if page := env.request(http.MethodGet,
		"/admin/users/password-reset?user_id=usr_reset", nil, ""); page.Code != http.StatusOK ||
		strings.Contains(page.Body.String(), `action="/admin/users/password-reset"`) {
		t.Fatalf("无权限页面 = %d body=%s", page.Code, page.Body.String())
	}
	backend3 := &fakeAdminBackend{canResetPassword: true,
		users: []login.UIAdminUserView{{UserID: "usr_reset", Username: "alice",
			Status: "active", RowVersion: 1}}}
	env3 := &adminPageEnv{t: t}
	ui3, err := login.NewWebUI(login.WebUIOptions{Session: adminPageSessions{},
		PageAdmin: &login.UIPageAdminOptions{Backend: backend3,
			DirectPasswordReset: backend3,
			ManagementSession: func(*http.Request) (string, bool) {
				return passwordResetPageSecret, true
			}}})
	if err != nil {
		t.Fatalf("框架: %v", err)
	}
	env3.handler = ui3
	mismatch := url.Values{"user_id": {"usr_reset"}, "new_password": {"a"},
		"new_password_confirm": {"b"}, "reason": {"r"}, "password": {"p"}}
	page := env3.post("/admin/users/password-reset", mismatch)
	if page.Code != http.StatusBadRequest || len(backend3.directPasswordCalls) != 0 {
		t.Fatalf("口令不一致应拒绝: %d calls=%v", page.Code, backend3.directPasswordCalls)
	}
}
