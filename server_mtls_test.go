package login

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// testClientCA 是 mTLS 测试用的客户端信任 CA（与服务器证书链独立）。
type testClientCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

// newTestClientCA 生成自签名客户端信任 CA，私钥只存在于内存。
func newTestClientCA(t *testing.T, commonName string) *testClientCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成客户端 CA 私钥失败：%v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发客户端 CA 失败：%v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析客户端 CA 失败：%v", err)
	}
	return &testClientCA{
		certificate: certificate,
		key:         key,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// writePEM 把 PEM 数据写入普通文件路径。
func writeTestPEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("写入测试 PEM 文件失败：%v", err)
	}
	return path
}

// issueClientCertificate 用客户端 CA 签发客户端叶证书，返回 TLS 证书与 PEM。
func (ca *testClientCA) issueClientCertificate(t *testing.T, template *x509.Certificate) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成客户端私钥失败：%v", err)
	}
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(time.Now().UnixNano())
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("签发客户端证书失败：%v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("编码客户端私钥失败：%v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("构造客户端证书对失败：%v", err)
	}
	chainPEM := certPEM
	return pair, chainPEM
}

// clientCertificateTemplate 返回客户端认证叶证书模板。
func clientCertificateTemplate(dnsNames ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: "mtls test client"},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// mtlsHTTPClient 返回信任测试服务器证书、按需强制发送客户端证书的 HTTPS 客户端。
func mtlsHTTPClient(pool *x509.CertPool, serverName string, certificate *tls.Certificate) *http.Client {
	config := &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	if certificate != nil {
		clientCert := *certificate
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: config},
	}
}

// identityTestHandler 返回把 mTLS 服务身份与客户端证书数量写入响应的 Handler。
func identityTestHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity, ok := ClientServiceIdentityFromContext(request.Context())
		peerCertificates := 0
		if request.TLS != nil {
			peerCertificates = len(request.TLS.PeerCertificates)
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(writer, fmt.Sprintf("identity=%s mapped=%t peer_certificates=%d",
			identity, ok, peerCertificates))
	})
}

// testMTLSIdentities 返回两条用于测试的身份映射。
func testMTLSIdentities() []TLSClientIdentity {
	return []TLSClientIdentity{
		{DNSName: "backup.internal", Service: "backup-agent"},
		{DNSName: "monitor.internal", Service: "monitor"},
	}
}

// testMTLSConfig 构造启用 mTLS 的可用配置。
func testMTLSConfig(t *testing.T, listenAddr, serverCertFile, serverKeyFile, clientCAFile string, mode TLSClientAuthMode) Config {
	t.Helper()
	cfg := testServerConfig(t, listenAddr)
	cfg.Server.TLSCertFiles = []string{serverCertFile}
	cfg.Server.TLSKeyFiles = []string{serverKeyFile}
	cfg.Server.TLSClientAuthMode = mode
	cfg.Server.TLSClientCAFiles = []string{clientCAFile}
	cfg.Server.TLSClientIdentities = testMTLSIdentities()
	return cfg
}

// requestMTLS 发起一次 HTTPS 请求并返回状态码与响应正文。
func requestMTLS(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("HTTPS 请求失败：%v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("读取响应失败：%v", err)
	}
	return response.StatusCode, string(body)
}

func TestServerMTLSRequiredEndToEnd(t *testing.T) {
	dir := testutil.TempDir(t)
	serverCert, serverKey, serverPool := generateTestServerCertificate(t, dir, "localhost")
	clientCA := newTestClientCA(t, "Login Client Trust CA")
	otherCA := newTestClientCA(t, "Untrusted Client CA")
	clientCAPath := writeTestPEM(t, dir, "client-ca.pem", clientCA.pem)
	cfg := testMTLSConfig(t, freeListenAddr(t), serverCert, serverKey, clientCAPath, TLSClientAuthRequired)
	_, server, boundAddr := startTLSTestServer(t, cfg, identityTestHandler())

	mappedCertificate, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	status, body := requestMTLS(t, mtlsHTTPClient(serverPool, "localhost", &mappedCertificate), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK {
		t.Fatalf("映射客户端证书请求 = %d %q", status, body)
	}
	if !strings.Contains(body, "identity=backup-agent mapped=true peer_certificates=1") {
		t.Errorf("处理程序观察到的 mTLS 身份 = %q", body)
	}

	tlsStatus, ok := server.TLSStatus()
	if !ok {
		t.Fatal("TLSStatus 应可用")
	}
	if tlsStatus.ClientAuth.Mode != TLSClientAuthRequired {
		t.Errorf("TLSStatus 客户端认证模式 = %q", tlsStatus.ClientAuth.Mode)
	}
	if len(tlsStatus.ClientAuth.TrustAnchors) != 1 || len(tlsStatus.ClientAuth.Identities) != 2 {
		t.Errorf("TLSStatus 客户端认证状态 = %+v", tlsStatus.ClientAuth)
	}
	if tlsStatus.ClientAuth.TrustAnchors[0].FingerprintSHA256 == "" {
		t.Error("TLSStatus 缺少客户端信任 CA 指纹")
	}

	// 失败路径：全部必须握手失败，客户端错误不得泄露映射或证书细节。
	wrongCA, _ := otherCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	unmapped, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("unknown.internal"))
	expiredTemplate := clientCertificateTemplate("backup.internal")
	expiredTemplate.NotBefore = time.Now().Add(-48 * time.Hour)
	expiredTemplate.NotAfter = time.Now().Add(-24 * time.Hour)
	expired, _ := clientCA.issueClientCertificate(t, expiredTemplate)
	wrongUsageTemplate := clientCertificateTemplate("backup.internal")
	wrongUsageTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	wrongUsage, _ := clientCA.issueClientCertificate(t, wrongUsageTemplate)
	ambiguous, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal", "monitor.internal"))

	failures := []struct {
		name        string
		certificate *tls.Certificate
	}{
		{"无客户端证书", nil},
		{"不受信任 CA", &wrongCA},
		{"身份未映射", &unmapped},
		{"客户端证书过期", &expired},
		{"用途错误", &wrongUsage},
		{"身份映射歧义", &ambiguous},
	}
	for _, failure := range failures {
		client := mtlsHTTPClient(serverPool, "localhost", failure.certificate)
		response, err := client.Get("https://" + boundAddr + "/healthz")
		if err == nil {
			response.Body.Close()
			t.Fatalf("%s 应握手失败", failure.name)
		}
		if strings.Contains(err.Error(), "backup.internal") || strings.Contains(err.Error(), "backup-agent") {
			t.Errorf("%s 的客户端错误泄露映射信息：%v", failure.name, err)
		}
	}
}

func TestServerMTLSOptionalEndToEnd(t *testing.T) {
	dir := testutil.TempDir(t)
	serverCert, serverKey, serverPool := generateTestServerCertificate(t, dir, "localhost")
	clientCA := newTestClientCA(t, "Login Client Trust CA")
	otherCA := newTestClientCA(t, "Untrusted Client CA")
	clientCAPath := writeTestPEM(t, dir, "client-ca.pem", clientCA.pem)
	cfg := testMTLSConfig(t, freeListenAddr(t), serverCert, serverKey, clientCAPath, TLSClientAuthOptional)
	_, _, boundAddr := startTLSTestServer(t, cfg, identityTestHandler())

	// 无证书：匿名连接允许，且没有服务身份。
	status, body := requestMTLS(t, mtlsHTTPClient(serverPool, "localhost", nil), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity= mapped=false peer_certificates=0") {
		t.Fatalf("可选模式匿名请求 = %d %q", status, body)
	}

	mapped, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	status, body = requestMTLS(t, mtlsHTTPClient(serverPool, "localhost", &mapped), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity=backup-agent") {
		t.Fatalf("可选模式映射证书请求 = %d %q", status, body)
	}

	// 关键不变量：出示无效或未映射证书不得降级为匿名。
	wrongCA, _ := otherCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	unmapped, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("unknown.internal"))
	expiredTemplate := clientCertificateTemplate("backup.internal")
	expiredTemplate.NotBefore = time.Now().Add(-48 * time.Hour)
	expiredTemplate.NotAfter = time.Now().Add(-24 * time.Hour)
	expired, _ := clientCA.issueClientCertificate(t, expiredTemplate)
	for _, failure := range []struct {
		name        string
		certificate *tls.Certificate
	}{
		{"不受信任 CA", &wrongCA},
		{"身份未映射", &unmapped},
		{"证书过期", &expired},
	} {
		response, err := mtlsHTTPClient(serverPool, "localhost", failure.certificate).Get("https://" + boundAddr + "/healthz")
		if err == nil {
			response.Body.Close()
			t.Fatalf("可选模式下 %s 应握手失败而不是降级为匿名", failure.name)
		}
	}
}

func TestServerMTLSDisabledKeepsAnonymous(t *testing.T) {
	dir := testutil.TempDir(t)
	serverCert, serverKey, serverPool := generateTestServerCertificate(t, dir, "localhost")
	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.TLSCertFiles = []string{serverCert}
	cfg.Server.TLSKeyFiles = []string{serverKey}
	_, server, boundAddr := startTLSTestServer(t, cfg, identityTestHandler())

	clientCA := newTestClientCA(t, "Unused Client CA")
	clientCertificate, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	status, body := requestMTLS(t, mtlsHTTPClient(serverPool, "localhost", &clientCertificate), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "peer_certificates=0") {
		t.Fatalf("关闭 mTLS 时应按匿名处理 = %d %q", status, body)
	}
	tlsStatus, _ := server.TLSStatus()
	if tlsStatus.ClientAuth.Mode != TLSClientAuthDisabled {
		t.Errorf("关闭 mTLS 时状态模式 = %q", tlsStatus.ClientAuth.Mode)
	}
}

func TestServerMTLSReloadKeepsClientAuth(t *testing.T) {
	dir := testutil.TempDir(t)
	serverCertFile, serverKeyFile, serverPool := generateTestServerCertificate(t, dir, "localhost")
	clientCA := newTestClientCA(t, "Login Client Trust CA")
	clientCAPath := writeTestPEM(t, dir, "client-ca.pem", clientCA.pem)
	cfg := testMTLSConfig(t, freeListenAddr(t), serverCertFile, serverKeyFile, clientCAPath, TLSClientAuthRequired)
	_, server, boundAddr := startTLSTestServer(t, cfg, identityTestHandler())
	mapped, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	mappedClient := mtlsHTTPClient(serverPool, "localhost", &mapped)
	status, body := requestMTLS(t, mappedClient, "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity=backup-agent") {
		t.Fatalf("重载前映射证书请求 = %d %q", status, body)
	}
	initialStatus, _ := server.TLSStatus()

	// 轮换服务器证书：ReloadTLS 只重载服务器证书，不得削弱客户端认证。
	newDir := testutil.TempDir(t)
	newCertFile, newKeyFile, newServerPool := generateTestServerCertificate(t, newDir, "localhost")
	if err := os.WriteFile(serverCertFile, mustReadFile(t, newCertFile), 0o644); err != nil {
		t.Fatalf("更新服务器证书失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(serverKeyFile, mustReadFile(t, newKeyFile)); err != nil {
		t.Fatalf("更新服务器私钥失败：%v", err)
	}
	if err := server.ReloadTLS(context.Background()); err != nil {
		t.Fatalf("服务器证书重载失败：%v", err)
	}
	// 新证书信任池的客户端仍需提供同一个客户端证书。
	status, body = requestMTLS(t, mtlsHTTPClient(newServerPool, "localhost", &mapped), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity=backup-agent") {
		t.Fatalf("重载后映射证书请求 = %d %q", status, body)
	}
	if _, err := mtlsHTTPClient(newServerPool, "localhost", nil).Get("https://" + boundAddr + "/healthz"); err == nil {
		t.Fatal("重载后无客户端证书仍应握手失败")
	}
	afterStatus, _ := server.TLSStatus()
	if afterStatus.ClientAuth.Mode != TLSClientAuthRequired ||
		len(afterStatus.ClientAuth.TrustAnchors) != len(initialStatus.ClientAuth.TrustAnchors) ||
		len(afterStatus.ClientAuth.Identities) != len(initialStatus.ClientAuth.Identities) {
		t.Errorf("重载改变了客户端认证状态：before=%+v after=%+v", initialStatus.ClientAuth, afterStatus.ClientAuth)
	}

	// 直接改写客户端信任 CA 文件不会影响运行中的服务：客户端信任配置不是热重载的。
	rotatedCA := newTestClientCA(t, "Rotated Client CA")
	if err := os.WriteFile(clientCAPath, rotatedCA.pem, 0o644); err != nil {
		t.Fatalf("改写客户端信任 CA 文件失败：%v", err)
	}
	rotatedCertificate, _ := rotatedCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	if _, err := mtlsHTTPClient(newServerPool, "localhost", &rotatedCertificate).Get("https://" + boundAddr + "/healthz"); err == nil {
		t.Fatal("运行中直接改写客户端信任 CA 不可热生效，新 CA 证书应被拒绝")
	}
	status, body = requestMTLS(t, mtlsHTTPClient(newServerPool, "localhost", &mapped), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity=backup-agent") {
		t.Fatalf("改写 CA 文件后旧信任仍应可用 = %d %q", status, body)
	}
}

func TestServerMTLSRevocationRequiresRestart(t *testing.T) {
	dir := testutil.TempDir(t)
	serverCert, serverKey, serverPool := generateTestServerCertificate(t, dir, "localhost")
	clientCA := newTestClientCA(t, "Login Client Trust CA")
	clientCAPath := writeTestPEM(t, dir, "client-ca.pem", clientCA.pem)
	mapped, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))

	// 第一代配置：backup.internal 映射到 backup-agent。
	cfg := testMTLSConfig(t, freeListenAddr(t), serverCert, serverKey, clientCAPath, TLSClientAuthRequired)
	instance, _, boundAddr := startTLSTestServer(t, cfg, identityTestHandler())
	status, body := requestMTLS(t, mtlsHTTPClient(serverPool, "localhost", &mapped), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity=backup-agent") {
		t.Fatalf("撤销前映射证书请求 = %d %q", status, body)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := instance.Close(closeCtx); err != nil {
		t.Fatalf("关闭第一代实例失败：%v", err)
	}

	// 模拟撤销：修改身份映射并重启（新实例），旧证书证书链仍有效但身份未映射。
	revokedConfig := cfg
	revokedConfig.Server.ListenAddr = freeListenAddr(t)
	revokedConfig.Server.TLSClientIdentities = []TLSClientIdentity{{DNSName: "monitor.internal", Service: "monitor"}}
	_, _, revokedAddr := startTLSTestServer(t, revokedConfig, identityTestHandler())
	if _, err := mtlsHTTPClient(serverPool, "localhost", &mapped).Get("https://" + revokedAddr + "/healthz"); err == nil {
		t.Fatal("重启撤销身份映射后旧证书应被拒绝")
	}
}

func TestServerMTLSShutdownReleasesPort(t *testing.T) {
	dir := testutil.TempDir(t)
	serverCert, serverKey, serverPool := generateTestServerCertificate(t, dir, "localhost")
	clientCA := newTestClientCA(t, "Login Client Trust CA")
	clientCAPath := writeTestPEM(t, dir, "client-ca.pem", clientCA.pem)
	cfg := testMTLSConfig(t, freeListenAddr(t), serverCert, serverKey, clientCAPath, TLSClientAuthRequired)
	instance, _, boundAddr := startTLSTestServer(t, cfg, identityTestHandler())
	mapped, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	client := mtlsHTTPClient(serverPool, "localhost", &mapped)
	status, body := requestMTLS(t, client, "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity=backup-agent") {
		t.Fatalf("关闭前 mTLS 请求 = %d %q", status, body)
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := instance.Close(closeCtx); err != nil {
		t.Fatalf("关闭 mTLS 实例失败：%v", err)
	}
	client.CloseIdleConnections()
	// 端口必须释放，重新监听成功即证明监听与已建立连接已清理。
	listener, err := net.Listen("tcp", boundAddr)
	if err != nil {
		t.Fatalf("关闭后端口未释放：%v", err)
	}
	_ = listener.Close()
	// 关闭后的 HTTPS 连接必须失败。
	if _, err := client.Get("https://" + boundAddr + "/healthz"); err == nil {
		t.Fatal("关闭后仍能建立 HTTPS 连接")
	}
}

func TestServerMTLSFromYAMLConfig(t *testing.T) {
	dir := testutil.TempDir(t)
	serverCert, serverKey, serverPool := generateTestServerCertificate(t, dir, "localhost")
	clientCA := newTestClientCA(t, "Login Client Trust CA")
	clientCAPath := writeTestPEM(t, dir, "client-ca.pem", clientCA.pem)
	yamlConfig := "server:\n" +
		"  listen_addr: \"" + freeListenAddr(t) + "\"\n" +
		"  tls_cert_files: [\"" + filepath.ToSlash(serverCert) + "\"]\n" +
		"  tls_key_files: [\"" + filepath.ToSlash(serverKey) + "\"]\n" +
		"  tls_client_auth: required\n" +
		"  tls_client_ca_files: [\"" + filepath.ToSlash(clientCAPath) + "\"]\n" +
		"  tls_client_identities:\n" +
		"    - dns_name: \"backup.internal\"\n" +
		"      service: \"backup-agent\"\n"
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlConfig)})
	cfg.Logging.Level = LogLevelError
	_, _, boundAddr := startTLSTestServer(t, cfg, identityTestHandler())
	mapped, _ := clientCA.issueClientCertificate(t, clientCertificateTemplate("backup.internal"))
	status, body := requestMTLS(t, mtlsHTTPClient(serverPool, "localhost", &mapped), "https://"+boundAddr+"/healthz")
	if status != http.StatusOK || !strings.Contains(body, "identity=backup-agent") {
		t.Fatalf("YAML 配置 mTLS 请求 = %d %q", status, body)
	}
}
