package transport

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBoundaryInjectsVerifiedClientServiceIdentity 验证代理边界把已验证客户端叶证书
// 的映射结果放入请求上下文，且不依赖任何请求头或请求体。
func TestBoundaryInjectsVerifiedClientServiceIdentity(t *testing.T) {
	peer := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "test client"},
		DNSNames: []string{"backup.internal"},
	}
	var (
		hasIdentity bool
		identity    string
	)
	handler, err := NewBoundary(BoundaryOptions{
		Next: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			identity, hasIdentity = ClientServiceIdentityFromContext(request.Context())
			writer.WriteHeader(http.StatusOK)
		}),
		ClientServiceIdentity: func(certificate *x509.Certificate) (string, bool) {
			if certificate == peer {
				return "backup-agent", true
			}
			return "", false
		},
		NewRequestID:      func() string { return "req_test" },
		ValidateRequestID: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("构造代理边界失败：%v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peer}}
	request.Header.Set("X-Client-Service-Identity", "spoofed-identity")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("状态 = %d：%s", recorder.Code, recorder.Body.String())
	}
	if !hasIdentity || identity != "backup-agent" {
		t.Fatalf("上下文服务身份 = %q/%v", identity, hasIdentity)
	}
}

// TestBoundaryClientServiceIdentityRequiresPeerCertificate 验证没有已验证客户端
// 证书时不会建立服务身份（匿名连接不能自称服务身份）。
func TestBoundaryClientServiceIdentityRequiresPeerCertificate(t *testing.T) {
	var (
		hasIdentity bool
		identity    string
	)
	resolverCalled := false
	handler, err := NewBoundary(BoundaryOptions{
		Next: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			identity, hasIdentity = ClientServiceIdentityFromContext(request.Context())
			writer.WriteHeader(http.StatusOK)
		}),
		ClientServiceIdentity: func(*x509.Certificate) (string, bool) {
			resolverCalled = true
			return "should-not-appear", true
		},
		NewRequestID:      func() string { return "req_test" },
		ValidateRequestID: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("构造代理边界失败：%v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.TLS = &tls.ConnectionState{}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("状态 = %d", recorder.Code)
	}
	if hasIdentity || identity != "" {
		t.Fatalf("没有客户端证书时不应建立服务身份：%q/%v", identity, hasIdentity)
	}
	if resolverCalled {
		t.Error("没有客户端证书时不应调用映射函数")
	}
}

// TestClientServiceIdentityContextIsolation 验证服务身份上下文键不能由普通值或
// 其他包的键伪造。
func TestClientServiceIdentityContextIsolation(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
	if identity, ok := ClientServiceIdentityFromContext(request.Context()); ok || identity != "" {
		t.Fatalf("空上下文应为无身份：%q/%v", identity, ok)
	}
	ctx := WithClientServiceIdentity(request.Context(), "  ")
	if identity, ok := ClientServiceIdentityFromContext(ctx); ok || identity != "" {
		t.Fatalf("空白身份不应写入上下文：%q/%v", identity, ok)
	}
}
