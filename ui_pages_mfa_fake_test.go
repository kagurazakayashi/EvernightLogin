package login

// 步骤 64 页面渲染测试（后端契约替身）：验证 Passkey/强初始化页面的服务端渲染
// 结构、数据属性与替代路径；真实服务集成见 login_test 的真实 SQLite 测试。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeMFABackend 实现 UIPageMFABackend 的页面结构测试替身。
type fakeMFABackend struct {
	view   UIPageSecondFactor
	start  UIPageStrongSetupStart
	result UIPageStrongSetupResult
	err    error
}

func (f *fakeMFABackend) LoadSecondFactor(context.Context, *http.Request) (UIPageSecondFactor, error) {
	return f.view, f.err
}
func (f *fakeMFABackend) VerifySecondFactor(context.Context, *http.Request,
	UIPageSecondFactorVerify) (UIPageSecondFactorResult, error) {
	return UIPageSecondFactorResult{}, nil
}
func (f *fakeMFABackend) ResendSecondFactor(context.Context, *http.Request) (UIPageSecondFactor, error) {
	return f.view, nil
}
func (f *fakeMFABackend) CancelSecondFactor(context.Context, *http.Request) (UIPageMFACancelResult, error) {
	return UIPageMFACancelResult{}, nil
}
func (f *fakeMFABackend) BeginStrongSetupPasskey(context.Context,
	*http.Request, string) (UIPageStrongSetupStart, error) {
	return f.start, nil
}
func (f *fakeMFABackend) FinishStrongSetupPasskey(context.Context, *http.Request,
	[]byte, string) (UIPageStrongSetupResult, error) {
	return f.result, nil
}
func (f *fakeMFABackend) BeginRecoveryCode(context.Context, *http.Request,
	UIPageRecoveryCodeRequest) (UIPageRecoveryBeginResult, error) {
	return UIPageRecoveryBeginResult{}, nil
}
func (f *fakeMFABackend) LoadRecovery(context.Context, *http.Request) (UIPageRecoverySnapshot, error) {
	return UIPageRecoverySnapshot{}, nil
}
func (f *fakeMFABackend) StartRecoveryRebind(context.Context, *http.Request,
	UIPageRecoveryRebindRequest) (UIPageRecoveryRebindStart, error) {
	return UIPageRecoveryRebindStart{}, nil
}
func (f *fakeMFABackend) CompleteRecoveryRebind(context.Context, *http.Request,
	UIPageRecoveryRebindComplete) (UIPageRecoveryCompletion, error) {
	return UIPageRecoveryCompletion{}, nil
}
func (f *fakeMFABackend) CancelRecovery(context.Context, *http.Request) (UIPageMFACancelResult, error) {
	return UIPageMFACancelResult{}, nil
}
func (f *fakeMFABackend) BeginPasswordReset(context.Context, *http.Request,
	UIPagePasswordForgotRequest) (UIPagePasswordForgotResult, error) {
	return UIPagePasswordForgotResult{}, nil
}
func (f *fakeMFABackend) ValidatePasswordReset(context.Context, *http.Request, string) error {
	return nil
}
func (f *fakeMFABackend) CompletePasswordReset(context.Context, *http.Request,
	UIPagePasswordResetRequest) (UIPagePasswordResetResult, error) {
	return UIPagePasswordResetResult{}, nil
}

// mfaTestWebUI 构造带步骤 64 页面的框架。
func mfaTestWebUI(t *testing.T, backend UIPageMFABackend) *WebUI {
	t.Helper()
	ui, err := NewWebUI(WebUIOptions{Prefix: "",
		PageMFA: &UIPageMFAOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("构造 MFA 页面失败: %v", err)
	}
	return ui
}

// serveMFATest 在内存中驱动页面。
func serveMFATest(ui *WebUI, method, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	if method == http.MethodPost {
		request = httptest.NewRequest(method, target, strings.NewReader("csrf_token=test-token"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// TestMFAPasskeyPageRendering 验证 Passkey 第二步页面只使用服务端 options，且
// 提供真实替代路径；不包含内联脚本或第三方资源。
func TestMFAPasskeyPageRendering(t *testing.T) {
	backend := &fakeMFABackend{view: UIPageSecondFactor{FactorType: "passkey",
		ChallengeID: "chal_1", AttemptToken: "attempt_1",
		PasskeyCeremonyID: "ceremony_1",
		PasskeyOptions:    []byte(`{"publicKey":{"challenge":"abc","rpId":"example.test"}}`)}}
	ui := mfaTestWebUI(t, backend)
	recorder := serveMFATest(ui, http.MethodGet, "/login/second-factor")
	if recorder.Code != http.StatusOK {
		t.Fatalf("Passkey 第二步页状态 = %d", recorder.Code)
	}
	body := recorder.Body.String()
	for _, expected := range []string{
		`data-ln-module="webauthn"`, `data-ln-mode="get"`,
		`data-ln-options="{&#34;publicKey&#34;:{&#34;challenge&#34;:&#34;abc&#34;,&#34;rpId&#34;:&#34;example.test&#34;}}"`,
		`name="passkey_ceremony_id" value="ceremony_1"`,
		`name="passkey_response"`, "调用认证器", "使用其他允许方式",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("Passkey 页面缺少 %q", expected)
		}
	}
	if strings.Contains(body, "<script>") || strings.Contains(body, "https://") {
		t.Fatal("Passkey 页面不得内联脚本或加载第三方资源")
	}
}

// TestMFAStrongSetupRendering 验证受限初始化页只列允许方法并加载真实注册 ceremony。
func TestMFAStrongSetupRendering(t *testing.T) {
	backend := &fakeMFABackend{view: UIPageSecondFactor{SetupRequired: true,
		AllowedMethods: []string{"passkey"}, FactorType: "passkey"},
		start: UIPageStrongSetupStart{CeremonyID: "ceremony_setup",
			PublicKey: []byte(`{"publicKey":{"challenge":"abc"}}`)},
		result: UIPageStrongSetupResult{UserID: "usr_x", ReloginRequired: true}}
	ui := mfaTestWebUI(t, backend)
	// 第二因素 GET 在初始化状态下转到强初始化页。
	if recorder := serveMFATest(ui, http.MethodGet, "/login/second-factor"); recorder.Code != http.StatusSeeOther ||
		recorder.Header().Get("Location") != "/login/strong-setup" {
		t.Fatalf("初始化状态应跳转强设置页，实际 %d %s", recorder.Code,
			recorder.Header().Get("Location"))
	}
	setup := serveMFATest(ui, http.MethodGet, "/login/strong-setup")
	if setup.Code != http.StatusOK || !strings.Contains(setup.Body.String(), "绑定符合要求的强认证方式") {
		t.Fatalf("强设置页状态 = %d", setup.Code)
	}
	start := serveMFATest(ui, http.MethodPost, "/login/strong-setup/passkey/start")
	if start.Code != http.StatusOK || !strings.Contains(start.Body.String(), "开始绑定 Passkey") {
		t.Fatalf("强设置注册开始失败: %d body=%s", start.Code, start.Body.String())
	}
	if !strings.Contains(start.Body.String(), `data-ln-mode="create"`) {
		t.Fatal("强设置页应加载 WebAuthn create ceremony")
	}
}

// TestMFAFormPathsAndRoutes 验证公开表单路径与命名路由冻结。
func TestMFAFormPathsAndRoutes(t *testing.T) {
	paths := UIPageMFAPublicFormPaths("/base")
	if paths["/base/login/second-factor"] != "auth.second_factor" ||
		paths["/base/login/reset-password"] != "auth.password_reset" {
		t.Fatalf("公开表单路径映射不正确: %+v", paths)
	}
	names := map[string]struct{}{}
	for _, name := range PageMFARouteNames() {
		if _, exists := names[name]; exists {
			t.Fatalf("路由名重复: %s", name)
		}
		names[name] = struct{}{}
	}
	ui := mfaTestWebUI(t, &fakeMFABackend{})
	registered := map[string]bool{}
	for _, route := range ui.Routes() {
		registered[route.Name] = true
	}
	for _, name := range PageMFARouteNames() {
		if !registered[name] {
			t.Errorf("步骤 64 路由未注册: %s", name)
		}
	}
}

// TestMFAInternalErrorFallback 验证真正内部故障返回 500 + 已翻译兜底，不泄露内部。
func TestMFAInternalErrorFallback(t *testing.T) {
	backend := &fakeMFABackend{err: errors.New("internal failed")}
	ui := mfaTestWebUI(t, backend)
	recorder := serveMFATest(ui, http.MethodGet, "/login/second-factor")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("内部故障应 500，实际 %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "INTERNAL_ERROR") || !strings.Contains(body, "服务暂时无法") {
		t.Fatalf("内部故障应显示翻译兜底，实际 body=%s", body[:min(len(body), 600)])
	}
	if strings.Contains(body, "internal failed") {
		t.Fatal("页面不得泄露内部错误文本")
	}
}
