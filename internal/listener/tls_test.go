package listener

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
)

// newTestTLSCertificate 生成自签名服务器证书与信任它的客户端证书池。
func newTestTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试私钥失败：%v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试证书失败：%v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析测试证书失败：%v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        certificate,
	}, pool
}

func TestTLSServeAndShutdown(t *testing.T) {
	certificate, roots := newTestTLSCertificate(t)
	server, err := New(Options{
		Addresses: []netpolicy.ListenAddress{mustAddress(t, "127.0.0.1:0")},
		Handler:   testHandler("tls-ok"),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		},
	})
	if err != nil {
		t.Fatalf("构造 TLS 监听器失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatalf("启动 TLS 监听失败：%v", err)
	}
	boundAddr := server.Addrs()[0].String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		}},
	}
	response, err := client.Get("https://" + boundAddr + "/")
	if err != nil {
		t.Fatalf("HTTPS 请求失败：%v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("读取响应失败：%v", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "tls-ok" {
		t.Fatalf("HTTPS 响应 = %d %q", response.StatusCode, body)
	}
	client.CloseIdleConnections()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("关闭 TLS 监听失败：%v", err)
	}
	assertPortReleasedOnHost(t, boundAddr)
}

// assertPortReleasedOnHost 在有界重试内确认端口可以重新绑定。
func assertPortReleasedOnHost(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for {
		listener, err := net.Listen("tcp", addr)
		if err == nil {
			_ = listener.Close()
			return
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("关闭后端口未释放：%v", lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
