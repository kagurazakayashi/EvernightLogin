package login_test

// 步骤 67 页面级测试：使用受控 UIPageSecurityBackend 验证路由/渲染/表单/状态。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/pagecsrf"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

type fakeSecurityBackend struct {
	removeMFA, revokeOthers, revokeAll, generate bool
	sessionPage                                  int
}

func (f *fakeSecurityBackend) GetOverview(context.Context, string) (login.UISecurityOverview, error) {
	return login.UISecurityOverview{EmailMFAEnabled: true, TOTPEnabled: true,
		PasskeyCount: 2, RecoveryAvailable: true, RecoveryRemaining: 5, ActiveSessions: 3}, nil
}
func (f *fakeSecurityBackend) ListMFA(context.Context, string) ([]login.UIMFAFactor, error) {
	return []login.UIMFAFactor{{Type: "email", State: "active", CreatedAt: time.Unix(0, 0)}}, nil
}
func (f *fakeSecurityBackend) BeginMFAEnrollment(context.Context, string, string) (login.UIMFAEnrollment, error) {
	return login.UIMFAEnrollment{ChallengeID: "chl_1", AttemptToken: "attempt-1",
		MaskedEmail: "a***@example.test", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}
func (f *fakeSecurityBackend) ConfirmMFAEnrollment(context.Context, string, login.UISecurityConfirm) error {
	return nil
}
func (f *fakeSecurityBackend) RemoveMFA(context.Context, string, string, string) error {
	f.removeMFA = true
	return nil
}
func (f *fakeSecurityBackend) GetTOTP(context.Context, string) (login.UITOTPState, error) {
	return login.UITOTPState{Enabled: false, Status: "unbound"}, nil
}
func (f *fakeSecurityBackend) BeginTOTP(context.Context, string, string) (login.UITOTPBinding, error) {
	return login.UITOTPBinding{BindingID: "totp_1", Secret: "JBSWY3DPEHPK3PXP",
		URI: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP", ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}
func (f *fakeSecurityBackend) ConfirmTOTP(context.Context, string, login.UISecurityConfirm) error {
	return nil
}
func (f *fakeSecurityBackend) RemoveTOTP(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeSecurityBackend) ListPasskeys(context.Context, string) ([]login.UIPasskey, error) {
	return nil, nil
}
func (f *fakeSecurityBackend) BeginPasskeyRegistration(context.Context, string, string) (login.UIPasskeyRegistration, error) {
	return login.UIPasskeyRegistration{CeremonyID: "cer_1", PublicKey: []byte(`{"challenge":"abc"}`),
		ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}
func (f *fakeSecurityBackend) FinishPasskeyRegistration(context.Context, string, login.UIPasskeyFinish) error {
	return nil
}
func (f *fakeSecurityBackend) RenamePasskey(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeSecurityBackend) RemovePasskey(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeSecurityBackend) GetRecoveryCodes(context.Context, string) (login.UIRecoveryInventory, error) {
	return login.UIRecoveryInventory{HasActiveGroup: true, Generation: 2, CodesRemaining: 5}, nil
}
func (f *fakeSecurityBackend) GenerateRecoveryCodes(context.Context, string, string, string, string) ([]string, error) {
	f.generate = true
	return []string{"AAAA-BBBB", "CCCC-DDDD"}, nil
}
func (f *fakeSecurityBackend) ListSessions(context.Context, *http.Request, int, int) (login.UISessionPage, error) {
	f.sessionPage++
	return login.UISessionPage{Page: 1, PageSize: 20, Total: 2, Sessions: []login.UISessionSummary{
		{ID: "ses_1", Current: true, Kind: "normal", ClientHint: "浏览器自述",
			AddressHint: "192.0.2.0/24", LastSeenAt: time.Now()},
		{ID: "ses_2", Kind: "normal", ClientHint: "其他"}},
	}, nil
}
func (f *fakeSecurityBackend) RevokeSession(context.Context, *http.Request, string, string, string) error {
	return nil
}
func (f *fakeSecurityBackend) RevokeOtherSessions(context.Context, *http.Request, string, string) (int64, error) {
	f.revokeOthers = true
	return 1, nil
}
func (f *fakeSecurityBackend) RevokeAllSessions(context.Context, *http.Request, string, string) (*http.Cookie, int64, error) {
	f.revokeAll = true
	return &http.Cookie{Name: "__Host-login_session", Value: "", MaxAge: -1}, 2, nil
}
func (f *fakeSecurityBackend) ListGrants(context.Context, *http.Request, int, int) (login.UIGrantPage, error) {
	return login.UIGrantPage{
		Page: 1, PageSize: 20, Total: 1,
		Grants: []login.UIGrant{{
			AuthorizationID: "aur_1", ApplicationName: "示例应用", ClientID: "app_1",
			ApprovedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
			Scopes: []login.UIPageScopeInfo{{Value: "email", Description: "邮箱"}},
		}},
	}, nil
}
func (f *fakeSecurityBackend) RevokeGrant(context.Context, *http.Request, string, string, string) (login.UIGrantRevokeResult, error) {
	return login.UIGrantRevokeResult{RefreshFamilies: 1}, nil
}

func newSecurityFakeUI(t *testing.T, backend *fakeSecurityBackend) *login.WebUI {
	t.Helper()
	keyring, err := secrets.GenerateKeyring("k1", time.Now())
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	tokens, err := pagecsrf.New(pagecsrf.Options{Keyring: keyring})
	if err != nil {
		t.Fatalf("页面令牌: %v", err)
	}
	ui, err := login.NewWebUI(login.WebUIOptions{Session: fakePageSessions{}, FormTokens: tokens,
		PageSecurity: &login.UIPageSecurityOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("安全中心页面: %v", err)
	}
	return ui
}

func securityRequest(ui *login.WebUI, method, target string, form url.Values) *httptest.ResponseRecorder {
	body := strings.NewReader("")
	if form != nil {
		body = strings.NewReader(form.Encode() + "&csrf_token=test-csrf-token")
	}
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Origin", "http://localhost")
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// TestSecurityPagesRendering 验证 22 条路由渲染、敏感表单目标与一次性秘密页面。
func TestSecurityPagesRendering(t *testing.T) {
	backend := &fakeSecurityBackend{}
	ui := newSecurityFakeUI(t, backend)
	get := func(path, expected string) {
		t.Helper()
		response := securityRequest(ui, http.MethodGet, path, nil)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("%s 渲染失败: %d", path, response.Code)
		}
	}
	get("/account/security", "安全设置")
	get("/account/security", "已启用")
	get("/account/security/mfa", "添加邮件验证码")
	get("/account/security/totp", "开始绑定验证器")
	get("/account/security/passkeys", "尚未添加 Passkey")
	get("/account/security/recovery-codes", "当前恢复代码组")
	get("/account/sessions", "当前会话")
	get("/account/grants", "示例应用")
	// TOTP 绑定页必须本地渲染 SVG 二维码，不出现纯文本种子。
	binding := securityRequest(ui, http.MethodPost, "/account/security/totp/bind", url.Values{"current_password": {"test-password"}})
	if binding.Code != http.StatusOK || !strings.Contains(binding.Body.String(), "<svg") ||
		strings.Contains(binding.Body.String(), "JBSWY3DPEHPK3PXP") {
		t.Fatalf("TOTP 绑定页二维码失败: %d body=%s", binding.Code, binding.Body.String())
	}
	// 邮件添加页只显示遮罩邮箱与一次性挑战字段，不回显验证码。
	addStart := securityRequest(ui, http.MethodPost, "/account/security/mfa", url.Values{})
	if addStart.Code != http.StatusOK || !strings.Contains(addStart.Body.String(), "a***@example.test") ||
		!strings.Contains(addStart.Body.String(), `name="attempt_token"`) {
		t.Fatalf("邮件添加页失败: %d", addStart.Code)
	}
	// 恢复代码只显示一次；“我已保存”不是上传证据。
	generate := securityRequest(ui, http.MethodPost, "/account/security/recovery-codes",
		url.Values{"confirm": {"true"}, "current_password": {"pw"}})
	if generate.Code != http.StatusOK || !strings.Contains(generate.Body.String(), "AAAA-BBBB") ||
		!backend.generate {
		t.Fatalf("恢复代码生成失败: %d", generate.Code)
	}
	// 退出全部携带清除 Cookie 并跳转登录。
	revokeAll := securityRequest(ui, http.MethodPost, "/account/sessions/revoke-all",
		url.Values{"current_password": {"pw"}})
	if revokeAll.Code != http.StatusSeeOther || !backend.revokeAll {
		t.Fatalf("退出全部会话失败: %d", revokeAll.Code)
	}
	// 撤回授权提交真实 AuthorizationID 与密码。
	revokeGrant := securityRequest(ui, http.MethodPost, "/account/grants/revoke",
		url.Values{"authorization_id": {"aur_1"}, "current_password": {"pw"}})
	if revokeGrant.Code != http.StatusOK || !strings.Contains(revokeGrant.Body.String(), "授权已撤回") {
		t.Fatalf("撤回授权失败: %d", revokeGrant.Code)
	}
	// 路由冻结。
	registered := map[string]bool{}
	for _, route := range ui.Routes() {
		registered[route.Name] = true
	}
	for _, name := range login.PageSecurityRouteNames() {
		if !registered[name] {
			t.Errorf("步骤 67 路由未注册: %s", name)
		}
	}
}
