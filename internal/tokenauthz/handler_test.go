package tokenauthz_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/authz"
	. "github.com/kagurazakayashi/EvernightLogin/internal/tokenauthz"
)

// fakeAuthenticator 是可信调用者认证器替身。
type fakeAuthenticator struct {
	service ResourceService
	err     error
	calls   int
}

func (f *fakeAuthenticator) AuthenticateResourceService(_ context.Context, _ *http.Request) (ResourceService, error) {
	f.calls++
	return f.service, f.err
}

// newHandlerEnv 构造带假认证器与判定服务的 HTTP 端点。
func newHandlerEnv(t *testing.T) (*HTTPHandler, *testEnv, *fakeAuthenticator) {
	t.Helper()
	env := newEnv(t)
	authenticator := &fakeAuthenticator{service: resource(t)}
	handler, err := NewHTTPHandler(HTTPOptions{Service: env.service, Authenticator: authenticator})
	if err != nil {
		t.Fatalf("构造 HTTP 端点失败: %v", err)
	}
	return handler, env, authenticator
}

// perform 发起一次请求并返回响应。
func perform(handler http.Handler, method, body string, header map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/api/v1/token-authorization", strings.NewReader(body))
	for key, value := range header {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestNewHTTPHandlerValidation 验证端点必需依赖与参数校验。
func TestNewHTTPHandlerValidation(t *testing.T) {
	env := newEnv(t)
	if _, err := NewHTTPHandler(HTTPOptions{Service: env.service}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("缺少调用者认证器应拒绝构造")
	}
	authenticator := &fakeAuthenticator{service: resource(t)}
	if _, err := NewHTTPHandler(HTTPOptions{Authenticator: authenticator}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("缺少判定服务应拒绝构造")
	}
	if _, err := NewHTTPHandler(HTTPOptions{Service: env.service, Authenticator: authenticator,
		MaxBodyBytes: 10}); !errors.Is(err, ErrOptionsInvalid) {
		t.Fatal("过小请求体上限应拒绝构造")
	}
}

// TestHTTPRejectsUnsupportedMethodAndBadBody 验证方法与请求体协议错误。
func TestHTTPRejectsUnsupportedMethodAndBadBody(t *testing.T) {
	handler, _, _ := newHandlerEnv(t)
	recorder := perform(handler, http.MethodGet, "", nil)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应返回 405，实际 %d", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("405 应声明允许方法，实际 %q", got)
	}
	cases := []struct {
		name string
		body string
	}{
		{"非法 JSON", "{"},
		{"未知字段（不能自称身份）", `{"access_token":"jwt","permissions":["invoices.approve"],"app_id":"app_00000000000000000000000000000001"}`},
		{"多余内容", `{"access_token":"jwt","permissions":["invoices.approve"]} {}`},
		{"空请求体", ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			recorder := perform(handler, http.MethodPost, test.body, nil)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("应返回 400，实际 %d（body=%s）", recorder.Code, recorder.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("错误响应不是 JSON: %v", err)
			}
			if payload["code"] != string(CodeReqInvalid) || payload["request_id"] == "" {
				t.Fatalf("错误信封缺少稳定码或 request_id: %s", recorder.Body.String())
			}
		})
	}
}

// TestHTTPCallerAuthentication 验证调用者身份只来自可信认证器。
func TestHTTPCallerAuthentication(t *testing.T) {
	handler, _, authenticator := newHandlerEnv(t)
	authenticator.err = errors.New("client auth failed")
	recorder := perform(handler, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"]}`, nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("认证失败应返回 401，实际 %d", recorder.Code)
	}
	var payload map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
	if payload["code"] != string(CodeClientAuthFailed) {
		t.Fatalf("认证失败错误码不正确: %s", recorder.Body.String())
	}
	// 认证器返回零值身份（实现缺陷）时，判定服务按不可信调用者拒绝。
	authenticator = &fakeAuthenticator{}
	handler2, err := NewHTTPHandler(HTTPOptions{Service: newEnv(t).service, Authenticator: authenticator})
	if err != nil {
		t.Fatalf("构造端点失败: %v", err)
	}
	recorder = perform(handler2, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"]}`, nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("零值身份应返回 403，实际 %d", recorder.Code)
	}
}

// TestHTTPDecisionResponses 验证业务允许/拒绝均返回 200 + allow 字段。
func TestHTTPDecisionResponses(t *testing.T) {
	handler, env, _ := newHandlerEnv(t)
	// 允许。
	recorder := perform(handler, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"]}`,
		map[string]string{"X-Request-ID": "req_http_1"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("业务判定应返回 200，实际 %d（%s）", recorder.Code, recorder.Body.String())
	}
	var decision Decision
	if err := json.Unmarshal(recorder.Body.Bytes(), &decision); err != nil {
		t.Fatalf("响应不是 Decision JSON: %v", err)
	}
	if !decision.Allow || decision.Subject != testUser || decision.ApplicationID != testAppOne {
		t.Fatalf("允许结果不正确: %+v", decision)
	}
	if decision.RequestID != "req_http_1" || recorder.Header().Get("X-Request-ID") != "req_http_1" {
		t.Fatalf("应复用合法客户端请求编号，实际 body=%q header=%q",
			decision.RequestID, recorder.Header().Get("X-Request-ID"))
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("判定响应必须禁止缓存")
	}
	// 拒绝：仍为 200 + allow=false + 稳定码。
	env.engine.setResult(authz.CheckResult{Allowed: false, Code: authz.CodePermissionRequired,
		Reason: "permission_not_granted"})
	recorder = perform(handler, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"]}`, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("业务拒绝应返回 200，实际 %d", recorder.Code)
	}
	decision = Decision{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decision); err != nil {
		t.Fatalf("响应不是 Decision JSON: %v", err)
	}
	if decision.Allow || decision.Code != CodePermissionRequired || decision.RequestID == "" {
		t.Fatalf("拒绝结果不正确: %+v", decision)
	}
}

// TestHTTPServiceErrors 验证协议/依赖错误映射为 4xx/5xx 统一信封。
func TestHTTPServiceErrors(t *testing.T) {
	handler, env, _ := newHandlerEnv(t)
	// 参数错误 400。
	recorder := perform(handler, http.MethodPost, `{"access_token":"","permissions":["invoices.approve"]}`, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("空令牌应返回 400，实际 %d", recorder.Code)
	}
	// 依赖不可用 503。
	env.revocation.err = errors.New("db down")
	recorder = perform(handler, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"]}`, nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("依赖不可用应返回 503，实际 %d", recorder.Code)
	}
	var payload map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
	if payload["code"] != string(CodeAuthzUnavailable) || payload["request_id"] == "" {
		t.Fatalf("503 错误信封不正确: %s", recorder.Body.String())
	}
}

// TestHTTPRequestIDHandling 验证非法客户端请求编号被忽略并生成新编号。
func TestHTTPRequestIDHandling(t *testing.T) {
	handler, _, _ := newHandlerEnv(t)
	recorder := perform(handler, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"]}`,
		map[string]string{"X-Request-ID": "bad id!"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("非法请求编号不应阻止判定，实际 %d", recorder.Code)
	}
	var decision Decision
	_ = json.Unmarshal(recorder.Body.Bytes(), &decision)
	if decision.RequestID == "bad id!" || !strings.HasPrefix(decision.RequestID, "azreq_") {
		t.Fatalf("应生成新请求编号而非回显非法值，实际 %q", decision.RequestID)
	}
}

// TestHTTPRequiredScopes 验证请求体支持所需 scope 且不足时按业务拒绝返回。
func TestHTTPRequiredScopes(t *testing.T) {
	handler, _, _ := newHandlerEnv(t)
	recorder := perform(handler, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"],"required_scopes":["openid"]}`, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("覆盖所需 scope 应通过，实际 %d（%s）", recorder.Code, recorder.Body.String())
	}
	recorder = perform(handler, http.MethodPost,
		`{"access_token":"jwt","permissions":["invoices.approve"],"required_scopes":["invoices.write"]}`, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("scope 不足应为业务拒绝 200，实际 %d", recorder.Code)
	}
	var decision Decision
	_ = json.Unmarshal(recorder.Body.Bytes(), &decision)
	if decision.Allow || decision.Code != CodeAccessDenied {
		t.Fatalf("scope 不足应返回 ACCESS_DENIED: %+v", decision)
	}
}

// TestHTTPBodyLimit 验证超大请求体按协议错误拒绝。
func TestHTTPBodyLimit(t *testing.T) {
	env := newEnv(t)
	authenticator := &fakeAuthenticator{service: resource(t)}
	handler, err := NewHTTPHandler(HTTPOptions{
		Service: env.service, Authenticator: authenticator, MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatalf("构造端点失败: %v", err)
	}
	large := `{"access_token":"` + strings.Repeat("a", 4096) + `","permissions":["invoices.approve"]}`
	recorder := perform(handler, http.MethodPost, large, nil)
	if recorder.Code != http.StatusRequestEntityTooLarge && recorder.Code != http.StatusBadRequest {
		t.Fatalf("超大请求体应返回 413/400，实际 %d", recorder.Code)
	}
}
