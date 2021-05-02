package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// boundaryCapture 记录内层处理程序收到的请求信息。
type boundaryCapture struct {
	called   bool
	host     string
	clientIP string
	headers  http.Header
}

func newBoundaryCapture(t *testing.T, options BoundaryOptions) (http.Handler, *boundaryCapture) {
	t.Helper()
	capture := &boundaryCapture{}
	options.Next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.called = true
		capture.host = r.Host
		capture.clientIP, _ = ClientIPFromContext(r.Context())
		capture.headers = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	handler, err := NewBoundary(options)
	if err != nil {
		t.Fatalf("构造代理边界失败：%v", err)
	}
	return handler, capture
}

func TestBoundaryLoopbackDefaultAndSpoofedHeaders(t *testing.T) {
	handler, capture := newBoundaryCapture(t, BoundaryOptions{})
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	request.RemoteAddr = "192.0.2.9:4444"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "evil.example.com")
	request.Header.Set("Forwarded", `for=203.0.113.99;host=evil.example.com`)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200：%s", recorder.Code, recorder.Body.String())
	}
	if !capture.called {
		t.Fatal("内层处理程序未被调用")
	}
	if capture.clientIP != "192.0.2.9" {
		t.Errorf("不可信对端伪造的转发头改变了客户端地址：%q", capture.clientIP)
	}
	for _, name := range proxyHeaderNames {
		if values := capture.headers.Values(name); len(values) > 0 {
			t.Errorf("内层仍能看到转发头 %s：%v", name, values)
		}
	}
}

func TestBoundaryRejectsUntrustedHost(t *testing.T) {
	handler, capture := newBoundaryCapture(t, BoundaryOptions{})
	request := httptest.NewRequest(http.MethodGet, "http://internal/healthz", nil)
	request.Host = "evil.example.com"
	request.RemoteAddr = "192.0.2.9:4444"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != hostRejectedStatus {
		t.Fatalf("状态 = %d，期望 %d", recorder.Code, hostRejectedStatus)
	}
	if capture.called {
		t.Fatal("不受信 Host 不应进入内层处理程序")
	}
	var payload struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("错误响应不是 JSON：%v", err)
	}
	if payload.Code != "REQ_INVALID" || payload.RequestID == "" {
		t.Fatalf("错误响应 = %+v", payload)
	}
	if recorder.Header().Get("X-Request-ID") == "" {
		t.Error("错误响应缺少 X-Request-ID")
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("错误响应缺少 nosniff")
	}
}

func TestBoundaryRejectsInvalidHost(t *testing.T) {
	handler, capture := newBoundaryCapture(t, BoundaryOptions{})
	cases := []struct {
		name string
		host string
	}{
		{name: "空 Host", host: ""},
		{name: "含空格", host: "bad host"},
		{name: "通配符", host: "*.example.com"},
		{name: "含路径", host: "example.com/path"},
		{name: "未加括号 IPv6", host: "2001:db8::1"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://internal/healthz", nil)
			request.Host = test.host
			request.RemoteAddr = "192.0.2.9:4444"
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("状态 = %d，期望 400", recorder.Code)
			}
			if capture.called {
				t.Fatal("无效 Host 不应进入内层处理程序")
			}
		})
	}
}

func TestBoundaryTrustedProxyChain(t *testing.T) {
	handler, capture := newBoundaryCapture(t, BoundaryOptions{
		TrustedProxies: []string{"10.0.0.1"},
		AllowedHosts:   []string{"login.example.com"},
	})
	request := httptest.NewRequest(http.MethodGet, "http://internal/healthz", nil)
	request.RemoteAddr = "10.0.0.1:5555"
	request.Header.Set("Forwarded", `for=198.51.100.7;proto=https;host="login.example.com"`)
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200：%s", recorder.Code, recorder.Body.String())
	}
	if capture.clientIP != "198.51.100.7" {
		t.Errorf("客户端地址 = %q，期望可信链解析结果", capture.clientIP)
	}
	if values := capture.headers.Values("Forwarded"); len(values) > 0 {
		t.Errorf("内层仍能看到 Forwarded：%v", values)
	}
}

func TestBoundaryTrustedForwardedHostMustBeAllowed(t *testing.T) {
	handler, capture := newBoundaryCapture(t, BoundaryOptions{
		TrustedProxies: []string{"10.0.0.1"},
		AllowedHosts:   []string{"login.example.com"},
	})
	request := httptest.NewRequest(http.MethodGet, "http://internal/healthz", nil)
	request.RemoteAddr = "10.0.0.1:5555"
	request.Header.Set("X-Forwarded-Host", "evil.example.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != hostRejectedStatus {
		t.Fatalf("状态 = %d，期望 %d", recorder.Code, hostRejectedStatus)
	}
	if capture.called {
		t.Fatal("不受信的转发主机不应进入内层处理程序")
	}
}

func TestBoundaryRejectsMalformedTrustedForwarding(t *testing.T) {
	handler, _ := newBoundaryCapture(t, BoundaryOptions{TrustedProxies: []string{"10.0.0.1"}})
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	request.RemoteAddr = "10.0.0.1:5555"
	request.Header.Set("Forwarded", `for=not-an-address`)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("状态 = %d，期望 400：%s", recorder.Code, recorder.Body.String())
	}
}

func TestBoundaryPublicBaseURLHost(t *testing.T) {
	handler, capture := newBoundaryCapture(t, BoundaryOptions{PublicBaseURL: "https://login.example.com/login"})
	allowed := httptest.NewRequest(http.MethodGet, "http://internal/healthz", nil)
	allowed.Host = "login.example.com"
	allowed.RemoteAddr = "192.0.2.9:4444"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, allowed)
	if recorder.Code != http.StatusOK || !capture.called {
		t.Fatalf("公开地址主机应允许：%d", recorder.Code)
	}

	denied := httptest.NewRequest(http.MethodGet, "http://internal/healthz", nil)
	denied.Host = "127.0.0.1:8080"
	denied.RemoteAddr = "192.0.2.9:4444"
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, denied)
	if recorder.Code != hostRejectedStatus {
		t.Fatalf("配置公开地址后回环主机也应被拒绝，实际 %d", recorder.Code)
	}
}

func TestBoundaryRequestIDHandling(t *testing.T) {
	handler, capture := newBoundaryCapture(t, BoundaryOptions{})
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	request.RemoteAddr = "192.0.2.9:4444"
	request.Header.Set("X-Request-ID", "req_client123")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("X-Request-ID"); got != "req_client123" {
		t.Errorf("响应请求编号 = %q，期望复用合法编号", got)
	}
	if got := capture.headers.Get("X-Request-ID"); got != "req_client123" {
		t.Errorf("内层请求编号 = %q", got)
	}

	invalid := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	invalid.RemoteAddr = "192.0.2.9:4444"
	invalid.Header.Set("X-Request-ID", "bad id with spaces")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, invalid)
	if got := recorder.Header().Get("X-Request-ID"); got == "" || got == "bad id with spaces" {
		t.Errorf("非法请求编号应被替换，实际 %q", got)
	}
}

func TestNewBoundaryValidation(t *testing.T) {
	validNext := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cases := []BoundaryOptions{
		{Next: nil},
		{Next: validNext, TrustedProxies: []string{"not-an-ip"}},
		{Next: validNext, AllowedHosts: []string{"*.example.com"}},
		{Next: validNext, PublicBaseURL: "ftp://login.example.com"},
		{Next: validNext, PublicBaseURL: "https://user:pass@login.example.com"},
	}
	for index, options := range cases {
		if _, err := NewBoundary(options); err == nil {
			t.Errorf("第 %d 个非法配置应被拒绝", index+1)
		}
	}
}
