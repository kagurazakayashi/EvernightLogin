package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeOAuthBackend struct {
	consent UIPageConsentPrompt
	device  UIPageDevicePrompt
	qr      UIPageQRBegin
	status  UIPageQRStatus
	scan    UIPageQRPrompt
}

func (f *fakeOAuthBackend) BeginConsent(context.Context, *http.Request, url.Values) (UIPageConsentPrompt, error) {
	return f.consent, nil
}
func (f *fakeOAuthBackend) DecideConsent(context.Context, *http.Request,
	UIPageConsentDecision) (UIPageConsentResult, error) {
	return UIPageConsentResult{Approved: true, RedirectURL: "https://client.example/cb?code=secret&state=s"}, nil
}
func (f *fakeOAuthBackend) DeviceDescribe(context.Context, *http.Request, string) (UIPageDevicePrompt, error) {
	return f.device, nil
}
func (f *fakeOAuthBackend) DeviceDecide(context.Context, *http.Request,
	UIPageDeviceDecision) (UIPageDeviceResult, error) {
	return UIPageDeviceResult{Approved: true, ApplicationName: "示例应用"}, nil
}
func (f *fakeOAuthBackend) BeginQR(context.Context, *http.Request) (UIPageQRBegin, error) {
	return f.qr, nil
}
func (f *fakeOAuthBackend) QueryQR(context.Context, *http.Request) (UIPageQRStatus, error) {
	return f.status, nil
}
func (f *fakeOAuthBackend) ClaimQR(context.Context, *http.Request) (UIPageQRClaim, error) {
	return UIPageQRClaim{}, nil
}
func (f *fakeOAuthBackend) RegenerateQR(context.Context, *http.Request) (UIPageQRBegin, error) {
	return f.qr, nil
}
func (f *fakeOAuthBackend) CancelQR(context.Context, *http.Request) (UIPageQRStatus, error) {
	return f.status, nil
}
func (f *fakeOAuthBackend) DescribeQR(context.Context, *http.Request, string) (UIPageQRPrompt, error) {
	return f.scan, nil
}
func (f *fakeOAuthBackend) DecideQR(context.Context, *http.Request,
	UIPageQRDecision) (UIPageQRPrompt, error) {
	return f.scan, nil
}

func oauthTestWebUI(t *testing.T, backend UIPageOAuthBackend) *WebUI {
	t.Helper()
	ui, err := NewWebUI(WebUIOptions{Prefix: "", PageOAuth: &UIPageOAuthOptions{Backend: backend}})
	if err != nil {
		t.Fatalf("构造 OAuth 页面失败: %v", err)
	}
	return ui
}

func serveOAuthPage(ui *WebUI, method, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	if method == http.MethodPost {
		body := "request_id=req_1&approve=true&user_code=ABCD-EFGH&csrf_token=x"
		if strings.HasPrefix(target, "/oauth/device") {
			body = "user_code=ABCD-EFGH&csrf_token=x"
		}
		request = httptest.NewRequest(method, target, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	recorder := httptest.NewRecorder()
	ui.ServeHTTP(recorder, request)
	return recorder
}

// TestOAuthPagesRendering 验证授权/设备/扫码页面只展示受控信息与真实决定表单。
func TestOAuthPagesRendering(t *testing.T) {
	backend := &fakeOAuthBackend{
		consent: UIPageConsentPrompt{RequestID: "req_1", ApplicationName: "示例应用",
			ClientID: "app_1", ClientType: "confidential", ExpiresAt: testMFATime(),
			UserDisplayName: "用户", RedirectURI: "https://client.example/cb",
			Scopes:    []UIPageScopeInfo{{Value: "openid", Description: "确认身份"}},
			Audiences: []UIPageAudienceInfo{{Value: "resource_1", Description: "目标资源"}}},
		device: UIPageDevicePrompt{RequestID: "req_2", ApplicationName: "示例应用",
			UserCode: "ABCD-EFGH", Scopes: []UIPageScopeInfo{{Value: "email", Description: "邮箱"}}},
		qr:     UIPageQRBegin{RequestID: "req_3", QRPayload: "evernight-login://app-qr?v=1&r=req_3", ExpiresAt: testMFATime(), PollIntervalSeconds: 5},
		status: UIPageQRStatus{Status: "approved", ExpiresAt: testMFATime()},
		scan: UIPageQRPrompt{RequestID: "req_3", ApplicationName: "示例应用",
			Status: "pending", Version: 1, ExpiresAt: testMFATime(), Warning: "只确认本人操作"},
	}
	ui := oauthTestWebUI(t, backend)
	// 授权页展示应用/scope/audience 与两个决定按钮。
	consent := serveOAuthPage(ui, http.MethodGet, "/oauth/authorize?client_id=app_1&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&response_type=code&code_challenge=abc&code_challenge_method=S256&scope=openid")
	if consent.Code != http.StatusOK || !strings.Contains(consent.Body.String(), "示例应用") ||
		!strings.Contains(consent.Body.String(), "确认身份") ||
		!strings.Contains(consent.Body.String(), "批准授权") ||
		!strings.Contains(consent.Body.String(), "拒绝授权") {
		t.Fatalf("授权页渲染不完整: %d", consent.Code)
	}
	// 设备页 GET 不提交决定；短码表单存在。
	device := serveOAuthPage(ui, http.MethodGet, "/oauth/device")
	if device.Code != http.StatusOK || !strings.Contains(device.Body.String(), "设备短码") {
		t.Fatalf("设备页渲染失败: %d", device.Code)
	}
	// 设备描述页显示应用与短码隐藏字段。
	describe := serveOAuthPage(ui, http.MethodPost, "/oauth/device")
	if describe.Code != http.StatusOK || !strings.Contains(describe.Body.String(), "ABCD-EFGH") ||
		!strings.Contains(describe.Body.String(), "确认设备授权") {
		t.Fatalf("设备确认页渲染失败: %d", describe.Code)
	}
	// 扫码发起页由服务端本地渲染内联 SVG 二维码与倒计时，不出现 ClaimSecret/外部资源。
	qr := serveOAuthPage(ui, http.MethodGet, "/login/qr")
	qrBody := qr.Body.String()
	if qr.Code != http.StatusOK || !strings.Contains(qrBody, "<svg") ||
		!strings.Contains(qrBody, `role="img"`) || !strings.Contains(qrBody, "<title>扫码登录二维码</title>") ||
		!strings.Contains(qrBody, "data-ln-deadline") || !strings.Contains(qrBody, "qr-countdown") ||
		!strings.Contains(qrBody, "<path") {
		t.Fatalf("扫码页未渲染本地 SVG 二维码/倒计时: %d", qr.Code)
	}
	if strings.Contains(qrBody, "claim_secret") || strings.Contains(qrBody, "<pre class=\"ln-secret\"") {
		t.Fatal("扫码页不得暴露 ClaimSecret 或仅以文本显示二维码载荷")
	}
	if strings.Contains(qrBody, `src="http`) || strings.Contains(qrBody, `href="http`) {
		t.Fatal("扫码页不得加载外部在线资源")
	}
	// 已登录 APP 确认页展示真实应用名与版本字段。
	scan := serveOAuthPage(ui, http.MethodGet, "/app/scan?request_id=req_3")
	if scan.Code != http.StatusOK || !strings.Contains(scan.Body.String(), "示例应用") ||
		!strings.Contains(scan.Body.String(), `name="expected_version"`) {
		t.Fatalf("APP 确认页渲染失败: %d", scan.Code)
	}
	// 匿名公开表单路径与路由冻结。
	if purpose := UIPageOAuthPublicFormPaths("/base")["/base/login/qr/poll"]; purpose != "auth.qr_login" {
		t.Fatalf("公开表单用途映射错误: %q", purpose)
	}
	registered := map[string]bool{}
	for _, route := range ui.Routes() {
		registered[route.Name] = true
	}
	for _, name := range PageOAuthRouteNames() {
		if !registered[name] {
			t.Errorf("步骤 65 路由未注册: %s", name)
		}
	}
}

// testMFATime 返回固定时间（测试展示用）。
func testMFATime() (result time.Time) { return time.Date(2026, 4, 5, 6, 0, 0, 0, time.UTC) }

// TestQRCodeServerRendering 验证服务端本地 QR SVG 内容与倒计时脚本具备过期/清理逻辑。
func TestQRCodeServerRendering(t *testing.T) {
	svg, err := renderQRSVG("evernight-login://app-qr?v=1&r=req_test")
	if err != nil {
		t.Fatalf("渲染二维码失败: %v", err)
	}
	body := string(svg)
	for _, expected := range []string{"<svg", `role="img"`, "<title>扫码登录二维码</title>",
		`class="ln-qr"`, "<path", "fill=\"#000000\""} {
		if !strings.Contains(body, expected) {
			t.Errorf("SVG 缺少 %q", expected)
		}
	}
	if _, err := renderQRSVG(""); err == nil {
		t.Fatal("空载荷应拒绝生成二维码")
	}
	// 倒计时/过期/清理逻辑在本地 ESM 中，不内联脚本、不引用外部资源。
	module, err := webEmbedded.ReadFile("web/assets/js/modules/qr.mjs")
	if err != nil {
		t.Fatalf("读取 qr 模块: %v", err)
	}
	for _, expected := range []string{"data-ln-deadline", "setTimeout", "clearTimeout",
		"expired", "Date.now()"} {
		if !strings.Contains(string(module), expected) {
			t.Errorf("qr 模块缺少 %q", expected)
		}
	}
	appModule, err := webEmbedded.ReadFile("web/assets/js/app.mjs")
	if err != nil || !strings.Contains(string(appModule), "qr-countdown") {
		t.Fatal("app.mjs 未注册 qr-countdown 模块")
	}
	for _, forbidden := range []string{"https://", "http://", "eval("} {
		if strings.Contains(string(module), forbidden) {
			t.Errorf("qr 模块不得包含 %q", forbidden)
		}
	}
}
