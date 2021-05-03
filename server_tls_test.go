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
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// generateTestServerCertificate 生成自签名服务器证书与受限权限私钥文件，返回
// 文件路径和信任该证书的客户端证书池。仅用于测试。
func generateTestServerCertificate(t *testing.T, dir string, domains ...string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试私钥失败：%v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: domains[0]},
		DNSNames:              domains,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试私钥失败：%v", err)
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("写入测试证书失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		t.Fatalf("写入受限权限测试私钥失败：%v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return certPath, keyPath, pool
}

// startTLSTestServer 构造并启动带本地 TLS 的监听服务。
func startTLSTestServer(t *testing.T, cfg Config, handler http.Handler) (*Instance, *Server, string) {
	t.Helper()
	server, err := NewServer(ServerOptions{Config: cfg, Handler: handler})
	if err != nil {
		t.Fatalf("构造 TLS 监听服务失败：%v", err)
	}
	if !server.TLSEnabled() {
		t.Fatal("配置了证书但 TLSEnabled 为 false")
	}
	instance, err := New(Options{Config: &cfg, Components: []BackgroundComponent{server}, LogOutput: io.Discard})
	if err != nil {
		t.Fatalf("构造实例失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := instance.Start(ctx); err != nil {
		t.Fatalf("启动 TLS 实例失败：%v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		_ = instance.Close(closeCtx)
	})
	return instance, server, server.Addrs()[0].String()
}

// httpsClient 返回信任指定证书池、校验主机名的 HTTPS 客户端。
func httpsClient(pool *x509.CertPool, serverName string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: serverName,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

func TestServerTLSHTTPSAndStatus(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := generateTestServerCertificate(t, dir, "localhost")
	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.TLSCertFiles = []string{certPath}
	cfg.Server.TLSKeyFiles = []string{keyPath}
	// 显式 0 表示使用默认到期告警窗口 30 天。
	cfg.Server.TLSExpiryWarningDays = 0
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, server, boundAddr := startTLSTestServer(t, cfg, handler)

	client := httpsClient(pool, "localhost")
	response, err := client.Get("https://" + boundAddr + "/healthz")
	if err != nil {
		t.Fatalf("HTTPS 请求失败：%v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != `{"status":"ok"}` {
		t.Fatalf("HTTPS 健康检查 = %d %q", response.StatusCode, body)
	}

	status, ok := server.TLSStatus()
	if !ok {
		t.Fatal("TLSStatus 应可用")
	}
	if len(status.Certificates) != 1 || status.Certificates[0].FingerprintSHA256 == "" {
		t.Fatalf("TLS 状态 = %+v", status)
	}
	if status.Expired || status.ExpiringSoon {
		t.Errorf("90 天有效期证书状态异常：%+v", status)
	}
	if len(status.Certificates[0].Domains) != 1 || status.Certificates[0].Domains[0] != "localhost" {
		t.Errorf("证书域名 = %v", status.Certificates[0].Domains)
	}
	// 证书不匹配的客户端主机名必须失败（不跳过校验）。
	if _, err := httpsClient(pool, "wrong.example.com").Get("https://" + boundAddr + "/healthz"); err == nil {
		t.Fatal("证书主机名不匹配时应握手失败")
	}
}

func TestServerTLSUnknownSNIRejected(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := generateTestServerCertificate(t, dir, "localhost")
	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.TLSCertFiles = []string{certPath}
	cfg.Server.TLSKeyFiles = []string{keyPath}
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, boundAddr := startTLSTestServer(t, cfg, handler)

	// 使用完整证书校验的客户端；未知 SNI 下服务端 GetCertificate 返回错误，
	// 握手失败（internal/tlscert 单元测试另行断言错误来自服务端选择逻辑）。
	if _, err := httpsClient(pool, "unknown.example.com").Get("https://" + boundAddr + "/healthz"); err == nil {
		t.Fatal("未知 SNI 应握手失败")
	}
}

func TestServerTLSValidationAtStartup(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := generateTestServerCertificate(t, dir, "login.example.com")
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("证书文件不存在", func(t *testing.T) {
		cfg := testServerConfig(t, freeListenAddr(t))
		cfg.Server.TLSCertFiles = []string{filepath.Join(dir, "missing.crt")}
		cfg.Server.TLSKeyFiles = []string{filepath.Join(dir, "missing.key")}
		if _, err := NewServer(ServerOptions{Config: cfg, Handler: handler}); err == nil {
			t.Fatal("不存在的证书文件应被拒绝")
		} else if appError, ok := AsAppError(err); !ok || appError.Code() != CodeConfigInvalid {
			t.Fatalf("错误应为 CONFIG_INVALID：%v", err)
		}
	})

	t.Run("允许主机未被证书覆盖", func(t *testing.T) {
		cfg := testServerConfig(t, freeListenAddr(t))
		cfg.Server.TLSCertFiles = []string{certPath}
		cfg.Server.TLSKeyFiles = []string{keyPath}
		cfg.Server.AllowedHosts = []string{"api.example.com"}
		if _, err := NewServer(ServerOptions{Config: cfg, Handler: handler}); err == nil {
			t.Fatal("证书未覆盖允许主机时应拒绝启动配置")
		}
	})

	t.Run("公开地址主机未被证书覆盖", func(t *testing.T) {
		cfg := testServerConfig(t, freeListenAddr(t))
		cfg.Server.TLSCertFiles = []string{certPath}
		cfg.Server.TLSKeyFiles = []string{keyPath}
		cfg.Server.PublicBaseURL = "https://other.example.com"
		if _, err := NewServer(ServerOptions{Config: cfg, Handler: handler}); err == nil {
			t.Fatal("证书未覆盖公开地址时应拒绝启动配置")
		}
	})

	t.Run("非回环监听在本地 TLS 下允许", func(t *testing.T) {
		cfg := testServerConfig(t, "0.0.0.0:8443")
		cfg.Server.TLSCertFiles = []string{certPath}
		cfg.Server.TLSKeyFiles = []string{keyPath}
		cfg.Server.PublicBaseURL = "https://login.example.com"
		// 只构造、不启动，避免真实绑定所有接口。
		if _, err := NewServer(ServerOptions{Config: cfg, Handler: handler}); err != nil {
			t.Fatalf("本地 TLS 下非回环监听应允许：%v", err)
		}
	})
}

func TestServerTLSReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := generateTestServerCertificate(t, dir, "localhost")
	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.TLSCertFiles = []string{certPath}
	cfg.Server.TLSKeyFiles = []string{keyPath}
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, server, boundAddr := startTLSTestServer(t, cfg, handler)
	client := httpsClient(pool, "localhost")
	if _, err := client.Get("https://" + boundAddr + "/healthz"); err != nil {
		t.Fatalf("初始 HTTPS 请求失败：%v", err)
	}
	initial, _ := server.TLSStatus()

	// 使用新的自签名证书替换（同一 SAN，同一信任池无法覆盖新证书，因此重新生成
	// 并信任新证书进行验证）。
	newDir := t.TempDir()
	newCertPath, newKeyPath, newPool := generateTestServerCertificate(t, newDir, "localhost")
	if err := os.WriteFile(certPath, mustReadFile(t, newCertPath), 0o644); err != nil {
		t.Fatalf("更新证书文件失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(keyPath, mustReadFile(t, newKeyPath)); err != nil {
		t.Fatalf("更新私钥文件失败：%v", err)
	}
	if err := server.ReloadTLS(context.Background()); err != nil {
		t.Fatalf("TLS 重载失败：%v", err)
	}
	reloaded, _ := server.TLSStatus()
	if reloaded.Certificates[0].FingerprintSHA256 == initial.Certificates[0].FingerprintSHA256 {
		t.Fatal("重载后证书指纹应变化")
	}
	if _, err := httpsClient(newPool, "localhost").Get("https://" + boundAddr + "/healthz"); err != nil {
		t.Fatalf("重载后新证书 HTTPS 请求失败：%v", err)
	}

	// 无效证书重载失败，继续使用旧证书。
	if err := os.WriteFile(certPath, []byte("broken"), 0o644); err != nil {
		t.Fatalf("写入无效证书失败：%v", err)
	}
	if err := server.ReloadTLS(context.Background()); err == nil {
		t.Fatal("无效证书重载应失败")
	} else if appError, ok := AsAppError(err); !ok || appError.Code() != CodeConfigInvalid {
		t.Fatalf("重载失败应为 CONFIG_INVALID：%v", err)
	}
	failed, _ := server.TLSStatus()
	if failed.Certificates[0].FingerprintSHA256 != reloaded.Certificates[0].FingerprintSHA256 {
		t.Fatal("重载失败后应保留旧证书")
	}
	if failed.ReloadFailures != 1 || !failed.LastReloadFailed {
		t.Fatalf("重载失败状态 = %+v", failed)
	}
	if _, err := httpsClient(newPool, "localhost").Get("https://" + boundAddr + "/healthz"); err != nil {
		t.Fatalf("重载失败后旧证书仍应可用：%v", err)
	}
}

func TestServerTLSReloadRejectsUncoveredCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := generateTestServerCertificate(t, dir, "localhost", "login.example.com")
	cfg := testServerConfig(t, freeListenAddr(t))
	cfg.Server.TLSCertFiles = []string{certPath}
	cfg.Server.TLSKeyFiles = []string{keyPath}
	cfg.Server.AllowedHosts = []string{"login.example.com"}
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// 同一份「不覆盖允许主机」的配置在启动阶段必须被拒绝。
	uncoveredDir := t.TempDir()
	uncoveredCert, uncoveredKey, _ := generateTestServerCertificate(t, uncoveredDir, "localhost")
	uncoveredCfg := testServerConfig(t, freeListenAddr(t))
	uncoveredCfg.Server.TLSCertFiles = []string{uncoveredCert}
	uncoveredCfg.Server.TLSKeyFiles = []string{uncoveredKey}
	uncoveredCfg.Server.AllowedHosts = []string{"login.example.com"}
	if _, err := NewServer(ServerOptions{Config: uncoveredCfg, Handler: handler}); err == nil {
		t.Fatal("启动阶段应拒绝未覆盖允许主机的证书")
	}

	_, server, boundAddr := startTLSTestServer(t, cfg, handler)
	initial, _ := server.TLSStatus()
	// 替换为只覆盖 localhost 的合法证书；重载必须被主机覆盖复验拒绝。
	if err := os.WriteFile(certPath, mustReadFile(t, uncoveredCert), 0o644); err != nil {
		t.Fatalf("更新证书文件失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(keyPath, mustReadFile(t, uncoveredKey)); err != nil {
		t.Fatalf("更新私钥文件失败：%v", err)
	}
	if err := server.ReloadTLS(context.Background()); err == nil {
		t.Fatal("未覆盖允许主机的证书重载应失败")
	} else if appError, ok := AsAppError(err); !ok || appError.Code() != CodeConfigInvalid {
		t.Fatalf("重载失败应为 CONFIG_INVALID：%v", err)
	}
	after, _ := server.TLSStatus()
	if after.Certificates[0].FingerprintSHA256 != initial.Certificates[0].FingerprintSHA256 {
		t.Fatal("重载被拒绝后应保留旧证书")
	}
	if after.ReloadFailures != 1 || !after.LastReloadFailed {
		t.Fatalf("重载被拒绝后的状态 = %+v", after)
	}
	// 旧证书仍可服务原允许主机（真实 TLS 握手，客户端使用 RootCAs 校验）。
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", boundAddr, &tls.Config{
		RootCAs:    pool,
		ServerName: "login.example.com",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("重载被拒绝后旧证书应仍可握手：%v", err)
	}
	_ = connection.Close()
}

// mustReadFile 读取测试证书文件。
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取测试证书失败：%v", err)
	}
	return data
}

func TestServerTLSPFXConfig(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, pool := generateTestServerCertificate(t, dir, "localhost")
	// 用测试证书/私钥重新编码为 PFX；私钥从受限文件中读取后仅用于测试编码。
	keyPEM := mustReadFile(t, keyPath)
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("解析测试私钥失败")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("解析测试私钥失败：%v", err)
	}
	certPEM := mustReadFile(t, certPath)
	certBlock, _ := pem.Decode(certPEM)
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("解析测试证书失败：%v", err)
	}
	password := "pfx-root-test"
	pfxData, err := pkcs12.Modern.Encode(key, certificate, nil, password)
	if err != nil {
		t.Fatalf("编码测试 PFX 失败：%v", err)
	}
	pfxPath := filepath.Join(dir, "server.pfx")
	if err := secrets.WriteProtectedFile(pfxPath, pfxData); err != nil {
		t.Fatalf("写入受限权限 PFX 失败：%v", err)
	}
	env := map[string]string{"LOGIN_TEST_PFX_PASSWORD": password}
	cfg := mustLoad(t, LoadOptions{
		YAML: yamlBytes("server:\n  listen_addr: \"" + freeListenAddr(t) + "\"\n  tls_pfx_file: \"" + filepath.ToSlash(pfxPath) + "\"\nsecrets:\n  tls_pfx_password:\n    env: LOGIN_TEST_PFX_PASSWORD\n"),
		LookupEnv: func(key string) (string, bool) {
			value, ok := env[key]
			return value, ok
		},
	})
	cfg.Logging.Level = LogLevelError
	handler, err := NewHTTPHandler(HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, boundAddr := startTLSTestServer(t, cfg, handler)
	if _, err := httpsClient(pool, "localhost").Get("https://" + boundAddr + "/healthz"); err != nil {
		t.Fatalf("PFX 配置 HTTPS 请求失败：%v", err)
	}
}
