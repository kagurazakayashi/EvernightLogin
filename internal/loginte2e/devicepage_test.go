package loginte2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestPageDeviceConfirmer 验证“驱动宿主设备确认页”的实验性适配器：读取页面隐藏
// 字段、带会话与同源 Origin 提交决定。它只测试适配器自身；宿主确认页是否存在、
// 是否满足安全要求由宿主页面层负责。
func TestPageDeviceConfirmer(t *testing.T) {
	const sessionSecret = "sess_0123456789abcdef0123456789abcdef"
	const issuer = "https://issuer.example.test"
	var (
		mu       sync.Mutex
		posted   bool
		formSeen map[string]string
	)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		switch request.URL.Path {
		case "/device-confirm":
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = writer.Write([]byte(`<!doctype html><html><body>
<form method="post" action="/device-confirm/decide">
<input type="hidden" name="csrf_token" value="csrf-test-value">
<input type="hidden" name="decision" value="deny">
</form></body></html>`))
		case "/device-confirm/decide":
			if err := request.ParseForm(); err != nil {
				t.Errorf("解析确认表单失败: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			posted = true
			formSeen = map[string]string{
				"authorization": request.Header.Get("Authorization"),
				"origin":        request.Header.Get("Origin"),
				"csrf":          request.PostForm.Get("csrf_token"),
				"decision":      request.PostForm.Get("decision"),
				"user_code":     request.PostForm.Get("user_code"),
			}
			mu.Unlock()
			writer.WriteHeader(http.StatusOK)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := New(Config{Server: server.URL, ExpectedIssuer: issuer,
		SessionSecret: sessionSecret, DeviceConfirmURL: "/device-confirm"})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	confirmer := (&Runner{client: client}).deviceConfirmer()
	if confirmer == nil {
		t.Fatal("配置了 DeviceConfirmURL 却未得到确认函数")
	}
	if err := confirmer(context.Background(), "ABCD-EFGH"); err != nil {
		t.Fatalf("驱动确认页失败: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !posted {
		t.Fatal("确认页表单未被提交")
	}
	if formSeen["authorization"] != "Bearer "+sessionSecret {
		t.Fatalf("确认页请求未带预期的会话凭据")
	}
	if formSeen["origin"] != issuer {
		t.Fatalf("确认页提交缺少同源 Origin：%q", formSeen["origin"])
	}
	if formSeen["csrf"] != "csrf-test-value" {
		t.Fatalf("确认页隐藏 CSRF 字段未原样提交")
	}
	if formSeen["decision"] != "approve" {
		t.Fatalf("决定字段 = %q，期望 approve", formSeen["decision"])
	}
	if formSeen["user_code"] != "ABCD-EFGH" {
		t.Fatalf("user_code 未带入表单：%q", formSeen["user_code"])
	}
}

// TestPageDeviceConfirmerRejectsForeignOrigin 验证确认页地址不允许跨源，避免把
// 会话秘密发送给其他主机。
func TestPageDeviceConfirmerRejectsForeignOrigin(t *testing.T) {
	client, err := New(Config{Server: "http://127.0.0.1:8080",
		SessionSecret: "sess_test", DeviceConfirmURL: "https://evil.example.test/confirm"})
	if err != nil {
		t.Fatalf("构造测试客户端失败: %v", err)
	}
	defer client.Close()
	confirmer := (&Runner{client: client}).deviceConfirmer()
	if err := confirmer(context.Background(), "CODE"); err == nil {
		t.Fatal("跨源确认页地址未被拒绝")
	} else if !strings.Contains(err.Error(), "同源") {
		t.Fatalf("错误信息未说明同源要求: %v", err)
	}
}
