package protocolapi

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newRecoveryTestServer 构造只含测试路由的最小 Server（不依赖数据库/真实服务），
// 用于验证最外层 router 的 panic 恢复契约。
func newRecoveryTestServer(routes map[string]http.Handler) *Server {
	return &Server{routes: routes, random: rand.Reader}
}

// TestRouterRecoversPanicWithUnifiedError 验证处理器 panic 时返回统一 500 错误：
// HTTP 500 + JSON code=INTERNAL_ERROR + 服务端 request_id，且响应不泄露 panic 值。
func TestRouterRecoversPanicWithUnifiedError(t *testing.T) {
	server := newRecoveryTestServer(map[string]http.Handler{
		"/panic": http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("boom-secret-detail")
		}),
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/panic", nil)
	server.router().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("panic 恢复状态 = %d，期望 500", recorder.Code)
	}
	headerRequestID := recorder.Header().Get(headerRequestID)
	if headerRequestID == "" {
		t.Fatal("panic 恢复响应缺少 X-Request-ID 头")
	}
	var payload struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("panic 恢复响应不是合法 JSON: %v\n%s", err, recorder.Body.String())
	}
	if payload.Code != codeInternalError {
		t.Fatalf("panic 恢复 code = %q，期望 %q", payload.Code, codeInternalError)
	}
	if payload.RequestID == "" || payload.RequestID != headerRequestID {
		t.Fatalf("panic 恢复 request_id 不一致: body=%q header=%q",
			payload.RequestID, headerRequestID)
	}
	for _, leaked := range []string{"boom-secret-detail", "goroutine", "panic", "runtime."} {
		if strings.Contains(recorder.Body.String(), leaked) {
			t.Fatalf("panic 恢复响应泄露内部细节 %q: %s", leaked, recorder.Body.String())
		}
	}
}

// TestRouterRecoversPanicAfterWrite 验证响应已写出后 panic 不会追加第二个响应。
func TestRouterRecoversPanicAfterWrite(t *testing.T) {
	server := newRecoveryTestServer(map[string]http.Handler{
		"/late-panic": http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"ok":true}`))
			panic("late failure")
		}),
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/late-panic", nil)
	// 不 panic 逸出：最外层必须恢复 panic，连接语义不被破坏。
	server.router().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("已写出响应的状态被改写为 %d", recorder.Code)
	}
	if recorder.Body.String() != `{"ok":true}` {
		t.Fatalf("已写出响应被追加内容: %q", recorder.Body.String())
	}
}

// TestRouterUnmatchedPathCarriesRequestID 验证未知路径 404 同时带 X-Request-ID 头
// 与 JSON request_id，并复用合法的客户端请求编号。
func TestRouterUnmatchedPathCarriesRequestID(t *testing.T) {
	server := newRecoveryTestServer(map[string]http.Handler{})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	request.Header.Set("X-Request-ID", "req_client_supplied_1")
	server.router().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("未知路径状态 = %d", recorder.Code)
	}
	responseRequestID := recorder.Header().Get(headerRequestID)
	if responseRequestID != "req_client_supplied_1" {
		t.Fatalf("未知路径 X-Request-ID = %q，应复用合法客户端编号", responseRequestID)
	}
	var payload struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("未知路径响应不是合法 JSON: %v", err)
	}
	if payload.Code != codeReqInvalid || payload.RequestID != responseRequestID {
		t.Fatalf("未知路径错误信封异常: %+v，header=%q", payload, responseRequestID)
	}

	// 非法客户端请求编号被忽略并生成服务端编号（不原样回显请求内容）。
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/unknown", nil)
	request.Header.Set("X-Request-ID", "bad request id")
	server.router().ServeHTTP(recorder, request)
	generated := recorder.Header().Get(headerRequestID)
	if generated == "" || generated == "bad request id" || !validRequestID(generated) {
		t.Fatalf("非法请求编号处理异常: %q", generated)
	}
}
