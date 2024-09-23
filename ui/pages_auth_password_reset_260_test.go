package ui

// 步骤 260：找回密码入口/页面按功能配置呈现的渲染测试（页面结构替身；真实
// 找回/三层路径成功失败链由 app 层集成测试覆盖）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAuthBackend 是最小 UIPageAuthBackend 替身（仅登录页渲染需要）。
type fakeAuthBackend struct{}

func (fakeAuthBackend) PasswordLogin(context.Context, *http.Request,
	UIPasswordLoginRequest) (UIPageLoginResult, error) {
	return UIPageLoginResult{}, nil
}
func (fakeAuthBackend) RegistrationAvailability(context.Context) (UIPageRegistrationAvailability, error) {
	return UIPageRegistrationAvailability{Enabled: true}, nil
}
func (fakeAuthBackend) Register(context.Context, UIRegisterRequest) (UIPageRegisterResult, error) {
	return UIPageRegisterResult{}, nil
}
func (fakeAuthBackend) VerifyEmail(context.Context, UIVerifyEmailRequest) (UIPageVerifyResult, error) {
	return UIPageVerifyResult{}, nil
}
func (fakeAuthBackend) ResendVerification(context.Context, *http.Request) (UIPageResendResult, error) {
	return UIPageResendResult{}, nil
}
func (fakeAuthBackend) AcceptInvitation(context.Context, *http.Request,
	UIPageInvitationAcceptRequest) (UIPageInvitationAcceptResult, error) {
	return UIPageInvitationAcceptResult{}, nil
}
func (fakeAuthBackend) Logout(context.Context, *http.Request) (*http.Cookie, error) {
	return nil, nil
}
func (fakeAuthBackend) BeginPasskeyLogin(context.Context, *http.Request) (UIPasskeyLoginStart, error) {
	return UIPasskeyLoginStart{}, nil
}
func (fakeAuthBackend) FinishPasskeyLogin(context.Context, *http.Request,
	[]byte) (UIPageLoginResult, error) {
	return UIPageLoginResult{}, nil
}

// TestLoginPagePasswordResetEntryByConfig 覆盖登录页“忘记密码”入口按配置显示/隐藏。
func TestLoginPagePasswordResetEntryByConfig(t *testing.T) {
	withPath, err := NewWebUI(WebUIOptions{PageAuth: &UIPageAuthOptions{
		Backend: fakeAuthBackend{}, PostLoginPath: "/home",
		PasswordResetPath: "/login/forgot-password"}})
	if err != nil {
		t.Fatalf("框架: %v", err)
	}
	recorder := httptest.NewRecorder()
	withPath.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://x/login", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, `href="/login/forgot-password"`) ||
		!strings.Contains(body, "使用邮件找回") {
		t.Fatalf("启用邮件找回时登录页缺少忘记密码入口: %s", body)
	}
	hidden, err := NewWebUI(WebUIOptions{PageAuth: &UIPageAuthOptions{
		Backend: fakeAuthBackend{}, PostLoginPath: "/home"}})
	if err != nil {
		t.Fatalf("框架: %v", err)
	}
	recorder = httptest.NewRecorder()
	hidden.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://x/login", nil))
	if strings.Contains(recorder.Body.String(), "/login/forgot-password") {
		t.Fatal("未启用邮件找回时登录页不应显示找回入口")
	}
}

// TestPasswordForgotPageAvailability 覆盖找回页在邮件能力未启用时给出稳定不可用
// 提示与下一路径，不渲染提交表单、不伪造已受理。
func TestPasswordForgotPageAvailability(t *testing.T) {
	unavailable := mfaTestWebUIWithAvailability(t, false)
	recorder := httptest.NewRecorder()
	unavailable.ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "http://x/login/forgot-password", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("找回页 = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "本部署未启用邮件找回能力") ||
		!strings.Contains(body, "恢复代码") {
		t.Fatalf("不可用提示缺少稳定说明/下一路径: %s", body)
	}
	if strings.Contains(body, `action="/login/forgot-password"`) {
		t.Fatal("邮件未启用时不应渲染找回提交表单")
	}
	available := mfaTestWebUIWithAvailability(t, true)
	recorder = httptest.NewRecorder()
	available.ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "http://x/login/forgot-password", nil))
	if !strings.Contains(recorder.Body.String(), `action="/login/forgot-password"`) {
		t.Fatal("邮件启用时应渲染找回提交表单")
	}
}

// mfaTestWebUIWithAvailability 构造带邮件找回可用性开关的页面框架。
func mfaTestWebUIWithAvailability(t *testing.T, available bool) *WebUI {
	t.Helper()
	ui, err := NewWebUI(WebUIOptions{PageMFA: &UIPageMFAOptions{
		Backend: &fakeMFABackend{}, PasswordResetAvailable: available}})
	if err != nil {
		t.Fatalf("构造 MFA 页面失败: %v", err)
	}
	return ui
}
