package tlscert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// testAuthority 是测试用证书颁发者（根 CA 或中间 CA）。
type testAuthority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	der         []byte
}

// newTestAuthority 生成自签名 CA。生成的私钥只存在于内存。
func newTestAuthority(t *testing.T, commonName string, isCA bool) *testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败：%v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if !isCA {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试 CA 失败：%v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析测试 CA 失败：%v", err)
	}
	return &testAuthority{certificate: certificate, key: key, der: der}
}

// issue 签发叶证书（或中间证书）。返回 DER 证书、私钥、PEM 编码。
func (authority *testAuthority) issue(t *testing.T, template *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成叶私钥失败：%v", err)
	}
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(time.Now().UnixNano())
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, &key.PublicKey, authority.key)
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
	return certificate, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// leafTemplate 返回服务器叶证书模板。
func leafTemplate(domains ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: domains[0]},
		DNSNames:              domains,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// writeProtected 用受保护文件写入秘密材料（私钥、PFX）；certificates 用普通
// 文件写入公共证书。
func writeProtected(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := secrets.WriteProtectedFile(path, data); err != nil {
		t.Fatalf("写入受保护文件失败：%v", err)
	}
	return path
}

func writePublic(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("写入公共文件失败：%v", err)
	}
	return path
}

// testIdentity 是一次测试证书文件的集合。
type testIdentity struct {
	ca       *testAuthority
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
	certPEM  []byte
	keyPEM   []byte
	certPath string
	keyPath  string
}

// newTestIdentity 在临时目录生成 CA + 叶证书及受保护私钥文件。
func newTestIdentity(t *testing.T, domains ...string) *testIdentity {
	t.Helper()
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Test Root CA", true)
	leaf, leafKey, certPEM, keyPEM := ca.issue(t, leafTemplate(domains...))
	return &testIdentity{
		ca:       ca,
		leaf:     leaf,
		leafKey:  leafKey,
		certPEM:  certPEM,
		keyPEM:   keyPEM,
		certPath: writePublic(t, dir, "server.crt", certPEM),
		keyPath:  writeProtected(t, dir, "server.key", keyPEM),
	}
}

// rootPool 返回信任测试根 CA 的证书池。
func (identity *testIdentity) rootPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(identity.ca.certificate)
	return pool
}

// handshake 用真实 TLS 握手验证服务端配置。客户端使用 RootCAs 校验，绝不设置
// InsecureSkipVerify。
func handshake(t *testing.T, manager *Manager, roots *x509.CertPool, serverName string, maxVersion uint16) error {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	serverTLS := tls.Server(serverConn, manager.TLSConfig())
	clientTLS := tls.Client(clientConn, &tls.Config{
		RootCAs:    roots,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		MaxVersion: maxVersion,
	})
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- serverTLS.Handshake()
	}()
	clientErr := clientTLS.Handshake()
	// 客户端失败时服务端也会返回错误；统一到通道并关闭连接以解除阻塞。
	_ = serverConn.Close()
	select {
	case <-serverResult:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("TLS 握手未在期限内完成")
	}
	return clientErr
}

func TestLoadPEMChainAndSNISelection(t *testing.T) {
	dir := testutil.TempDir(t)
	root := newTestAuthority(t, "Root CA", true)
	intermediate, intermediateKey, intermediatePEM, intermediateKeyPEM := root.issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(60 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	})
	_ = intermediate
	leafAuthority := &testAuthority{certificate: intermediate, key: intermediateKey}
	leaf, _, leafPEM, leafKeyPEM := leafAuthority.issue(t, leafTemplate("login.example.com", "*.example.org"))
	certPath := writePublic(t, dir, "chain.crt", append(append(append([]byte{}, leafPEM...), intermediatePEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.der})...))
	keyPath := writeProtected(t, dir, "leaf.key", leafKeyPEM)
	_ = leaf
	_ = intermediateKeyPEM

	manager, err := New(Options{Source: Source{CertFiles: []string{certPath}, KeyFiles: []string{keyPath}}})
	if err != nil {
		t.Fatalf("加载证书链失败：%v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.certificate)
	if err := handshake(t, manager, roots, "login.example.com", 0); err != nil {
		t.Fatalf("精确域名握手失败：%v", err)
	}
	if err := handshake(t, manager, roots, "app.example.org", 0); err != nil {
		t.Fatalf("通配符域名握手失败：%v", err)
	}
	if err := handshake(t, manager, roots, "unknown.example.com", 0); err == nil {
		t.Fatal("未知 SNI 应握手失败")
	}
	if err := handshake(t, manager, roots, "login.example.com", tls.VersionTLS11); err == nil {
		t.Fatal("TLS 1.1 客户端应被拒绝")
	}
	status := manager.Status()
	if len(status.Certificates) != 1 {
		t.Fatalf("证书状态数量 = %d", len(status.Certificates))
	}
	if status.Expired || status.ExpiringSoon {
		t.Errorf("90 天有效期证书不应到期：%+v", status)
	}
	if len(status.Certificates[0].Domains) != 2 {
		t.Errorf("证书域名 = %v", status.Certificates[0].Domains)
	}
}

func TestDefaultCertificateForEmptySNI(t *testing.T) {
	identity := newTestIdentity(t, "login.example.com")
	manager, err := New(Options{Source: Source{CertFiles: []string{identity.certPath}, KeyFiles: []string{identity.keyPath}}})
	if err != nil {
		t.Fatalf("加载证书失败：%v", err)
	}
	certificate, err := manager.tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || certificate == nil {
		t.Fatalf("无 SNI 应选择默认证书：%v", err)
	}
	if _, err := manager.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("未知 SNI 应返回错误")
	}
	if _, err := manager.tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "LOGIN.EXAMPLE.COM."}); err != nil {
		t.Fatalf("大小写与结尾点应被规范化：%v", err)
	}
}

func TestCertificateValidationFailures(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Root", true)
	_, _, leafPEM, leafKeyPEM := ca.issue(t, leafTemplate("login.example.com"))
	_, _, otherPEM, otherKeyPEM := ca.issue(t, leafTemplate("other.example.com"))
	certPath := writePublic(t, dir, "server.crt", leafPEM)
	keyPath := writeProtected(t, dir, "server.key", leafKeyPEM)
	_ = writePublic(t, dir, "other.crt", otherPEM)
	otherKeyPath := writeProtected(t, dir, "other.key", otherKeyPEM)

	if _, err := New(Options{Source: Source{CertFiles: []string{certPath}, KeyFiles: []string{otherKeyPath}}}); err == nil {
		t.Fatal("私钥与证书不匹配应被拒绝")
	}
	if _, err := New(Options{Source: Source{CertFiles: []string{certPath}, KeyFiles: []string{certPath}}}); err == nil {
		t.Fatal("把证书当私钥应被拒绝")
	}
	garbagePath := writePublic(t, dir, "garbage.crt", []byte("not a certificate"))
	if _, err := New(Options{Source: Source{CertFiles: []string{garbagePath}, KeyFiles: []string{keyPath}}}); err == nil {
		t.Fatal("畸形证书应被拒绝")
	}

	// 已过期叶证书。
	expiredTemplate := leafTemplate("expired.example.com")
	expiredTemplate.NotBefore = time.Now().Add(-48 * time.Hour)
	expiredTemplate.NotAfter = time.Now().Add(-24 * time.Hour)
	_, _, expiredPEM, expiredKeyPEM := ca.issue(t, expiredTemplate)
	expiredCertPath := writePublic(t, dir, "expired.crt", expiredPEM)
	expiredKeyPath := writeProtected(t, dir, "expired.key", expiredKeyPEM)
	if _, err := New(Options{Source: Source{CertFiles: []string{expiredCertPath}, KeyFiles: []string{expiredKeyPath}}}); err == nil {
		t.Fatal("已过期证书应被拒绝")
	}

	// 尚未生效的证书。
	futureTemplate := leafTemplate("future.example.com")
	futureTemplate.NotBefore = time.Now().Add(24 * time.Hour)
	futureTemplate.NotAfter = time.Now().Add(48 * time.Hour)
	_, _, futurePEM, futureKeyPEM := ca.issue(t, futureTemplate)
	futureCertPath := writePublic(t, dir, "future.crt", futurePEM)
	futureKeyPath := writeProtected(t, dir, "future.key", futureKeyPEM)
	if _, err := New(Options{Source: Source{CertFiles: []string{futureCertPath}, KeyFiles: []string{futureKeyPath}}}); err == nil {
		t.Fatal("尚未生效证书应被拒绝")
	}

	// 无 DNS SAN。
	noSAN := leafTemplate("login.example.com")
	noSAN.DNSNames = nil
	_, _, noSANPEM, noSANKeyPEM := ca.issue(t, noSAN)
	noSANPath := writePublic(t, dir, "nosan.crt", noSANPEM)
	noSANKeyPath := writeProtected(t, dir, "nosan.key", noSANKeyPEM)
	if _, err := New(Options{Source: Source{CertFiles: []string{noSANPath}, KeyFiles: []string{noSANKeyPath}}}); err == nil {
		t.Fatal("缺少 DNS SAN 的证书应被拒绝")
	}

	// 通配符裸域名。
	badWildcard := leafTemplate("*.com")
	_, _, badWildcardPEM, badWildcardKeyPEM := ca.issue(t, badWildcard)
	badWildcardPath := writePublic(t, dir, "bad-wildcard.crt", badWildcardPEM)
	badWildcardKeyPath := writeProtected(t, dir, "bad-wildcard.key", badWildcardKeyPEM)
	if _, err := New(Options{Source: Source{CertFiles: []string{badWildcardPath}, KeyFiles: []string{badWildcardKeyPath}}}); err == nil {
		t.Fatal("通配 *.com 应被拒绝")
	}
}

func TestChainOrganizationFailures(t *testing.T) {
	dir := testutil.TempDir(t)
	root := newTestAuthority(t, "Root", true)
	intermediate, intermediateKey, intermediatePEM, _ := root.issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(60 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	leafAuthority := &testAuthority{certificate: intermediate, key: intermediateKey}
	_, _, leafPEM, leafKeyPEM := leafAuthority.issue(t, leafTemplate("login.example.com"))
	keyPath := writeProtected(t, dir, "leaf.key", leafKeyPEM)

	// 链顺序错误：根证书放在中间证书之前。
	outOfOrder := append(append([]byte{}, leafPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.der})...)
	outOfOrder = append(outOfOrder, intermediatePEM...)
	outOfOrderPath := writePublic(t, dir, "out-of-order.crt", outOfOrder)
	if _, err := New(Options{Source: Source{CertFiles: []string{outOfOrderPath}, KeyFiles: []string{keyPath}}}); err == nil {
		t.Fatal("证书链顺序错误应被拒绝")
	}

	// 重复证书。
	duplicated := append(append([]byte{}, leafPEM...), intermediatePEM...)
	duplicated = append(duplicated, intermediatePEM...)
	duplicatedPath := writePublic(t, dir, "duplicated.crt", duplicated)
	if _, err := New(Options{Source: Source{CertFiles: []string{duplicatedPath}, KeyFiles: []string{keyPath}}}); err == nil {
		t.Fatal("重复证书应被拒绝")
	}

	// 签发者不是 CA。
	notCA := newTestAuthority(t, "Not CA", false)
	leafAuthority2 := &testAuthority{certificate: notCA.certificate, key: notCA.key}
	_, _, leaf2PEM, leaf2KeyPEM := leafAuthority2.issue(t, leafTemplate("login.example.com"))
	leaf2KeyPath := writeProtected(t, dir, "leaf2.key", leaf2KeyPEM)
	notCAChain := append(append([]byte{}, leaf2PEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: notCA.der})...)
	notCAChainPath := writePublic(t, dir, "not-ca.crt", notCAChain)
	if _, err := New(Options{Source: Source{CertFiles: []string{notCAChainPath}, KeyFiles: []string{leaf2KeyPath}}}); err == nil {
		t.Fatal("非 CA 证书不能作为签发者")
	}
}

func TestAdditionalCAFile(t *testing.T) {
	dir := testutil.TempDir(t)
	root := newTestAuthority(t, "Root", true)
	intermediate, intermediateKey, intermediatePEM, _ := root.issue(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(60 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	})
	leafAuthority := &testAuthority{certificate: intermediate, key: intermediateKey}
	_, _, leafPEM, leafKeyPEM := leafAuthority.issue(t, leafTemplate("login.example.com"))
	certPath := writePublic(t, dir, "leaf-only.crt", leafPEM)
	keyPath := writeProtected(t, dir, "leaf.key", leafKeyPEM)
	caPath := writePublic(t, dir, "ca.pem", intermediatePEM)

	manager, err := New(Options{Source: Source{CertFiles: []string{certPath}, KeyFiles: []string{keyPath}, CAFile: caPath}})
	if err != nil {
		t.Fatalf("附加 CA 文件加载失败：%v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.certificate)
	if err := handshake(t, manager, roots, "login.example.com", 0); err != nil {
		t.Fatalf("附加 CA 文件后握手失败：%v", err)
	}
}

func TestPFXImport(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Root", true)
	leaf, leafKey, _, _ := ca.issue(t, leafTemplate("login.example.com"))
	password := "pfx-test-password"
	pfxData, err := pkcs12.Modern.Encode(leafKey, leaf, []*x509.Certificate{ca.certificate}, password)
	if err != nil {
		t.Fatalf("编码测试 PFX 失败：%v", err)
	}
	pfxPath := writeProtected(t, dir, "server.pfx", pfxData)

	manager, err := New(Options{Source: Source{PFXFile: pfxPath, PFXPassword: []byte(password)}})
	if err != nil {
		t.Fatalf("PFX 加载失败：%v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)
	if err := handshake(t, manager, roots, "login.example.com", 0); err != nil {
		t.Fatalf("PFX 证书握手失败：%v", err)
	}

	if _, err := New(Options{Source: Source{PFXFile: pfxPath, PFXPassword: []byte("wrong-password")}}); err == nil {
		t.Fatal("错误 PFX 密码应被拒绝")
	}
	if _, err := New(Options{Source: Source{PFXFile: pfxPath}}); err == nil {
		t.Fatal("缺少 PFX 密码应被拒绝")
	}
}

func TestDuplicateDomainsAcrossCertificates(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Root", true)
	_, _, certPEM1, keyPEM1 := ca.issue(t, leafTemplate("login.example.com"))
	_, _, certPEM2, keyPEM2 := ca.issue(t, leafTemplate("login.example.com"))
	cert1 := writePublic(t, dir, "one.crt", certPEM1)
	key1 := writeProtected(t, dir, "one.key", keyPEM1)
	cert2 := writePublic(t, dir, "two.crt", certPEM2)
	key2 := writeProtected(t, dir, "two.key", keyPEM2)
	if _, err := New(Options{Source: Source{
		CertFiles: []string{cert1, cert2},
		KeyFiles:  []string{key1, key2},
	}}); err == nil {
		t.Fatal("重复 DNS 名称的多个证书身份应被拒绝")
	}
}

func TestReloadSuccessAndFailureFallback(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Root", true)
	_, _, certPEM1, keyPEM1 := ca.issue(t, leafTemplate("login.example.com"))
	certPath := writePublic(t, dir, "server.crt", certPEM1)
	keyPath := writeProtected(t, dir, "server.key", keyPEM1)
	manager, err := New(Options{Source: Source{CertFiles: []string{certPath}, KeyFiles: []string{keyPath}}})
	if err != nil {
		t.Fatalf("加载证书失败：%v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)
	if err := handshake(t, manager, roots, "login.example.com", 0); err != nil {
		t.Fatalf("初始握手失败：%v", err)
	}
	initial := manager.Status()

	// 使用同一 CA 重新签发（相同域名、不同序列号/指纹）。
	_, _, certPEM2, keyPEM2 := ca.issue(t, leafTemplate("login.example.com"))
	if err := os.WriteFile(certPath, certPEM2, 0o644); err != nil {
		t.Fatalf("更新证书文件失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(keyPath, keyPEM2); err != nil {
		t.Fatalf("更新私钥文件失败：%v", err)
	}
	if err := manager.Reload(context.Background()); err != nil {
		t.Fatalf("重载失败：%v", err)
	}
	reloaded := manager.Status()
	if reloaded.Certificates[0].FingerprintSHA256 == initial.Certificates[0].FingerprintSHA256 {
		t.Fatal("重载后证书指纹应变化")
	}
	if err := handshake(t, manager, roots, "login.example.com", 0); err != nil {
		t.Fatalf("重载后握手失败：%v", err)
	}

	// 写入无效证书后重载失败，必须继续使用旧证书。
	if err := os.WriteFile(certPath, []byte("broken"), 0o644); err != nil {
		t.Fatalf("写入无效证书失败：%v", err)
	}
	if err := manager.Reload(context.Background()); err == nil {
		t.Fatal("无效证书重载应失败")
	}
	failed := manager.Status()
	if failed.Certificates[0].FingerprintSHA256 != reloaded.Certificates[0].FingerprintSHA256 {
		t.Fatal("重载失败后应保留旧证书")
	}
	if failed.ReloadFailures != 1 || !failed.LastReloadFailed {
		t.Fatalf("重载失败状态 = %+v", failed)
	}
	if err := handshake(t, manager, roots, "login.example.com", 0); err != nil {
		t.Fatalf("重载失败后旧证书仍应可用：%v", err)
	}
	if err := manager.Reload(nil); err == nil {
		t.Fatal("无效证书再次重载仍应失败")
	}
}

func TestConcurrentHandshakeDuringReload(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Root", true)
	_, _, certPEM, keyPEM := ca.issue(t, leafTemplate("login.example.com"))
	certPath := writePublic(t, dir, "server.crt", certPEM)
	keyPath := writeProtected(t, dir, "server.key", keyPEM)
	manager, err := New(Options{Source: Source{CertFiles: []string{certPath}, KeyFiles: []string{keyPath}}})
	if err != nil {
		t.Fatalf("加载证书失败：%v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.certificate)

	var waitGroup sync.WaitGroup
	errors := make(chan error, 1)
	stop := make(chan struct{})
	for worker := 0; worker < 6; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := handshake(t, manager, roots, "login.example.com", 0); err != nil {
					select {
					case errors <- err:
					default:
					}
					return
				}
			}
		}()
	}

	for attempt := 0; attempt < 6; attempt++ {
		_, _, newCertPEM, newKeyPEM := ca.issue(t, leafTemplate("login.example.com"))
		if err := os.WriteFile(certPath, newCertPEM, 0o644); err != nil {
			t.Fatalf("更新证书文件失败：%v", err)
		}
		if err := secrets.WriteProtectedFile(keyPath, newKeyPEM); err != nil {
			t.Fatalf("更新私钥文件失败：%v", err)
		}
		if err := manager.Reload(context.Background()); err != nil {
			t.Fatalf("第 %d 次重载失败：%v", attempt+1, err)
		}
	}
	// 并发握手仍在进行时制造一次重载失败：握手不得中断，失败后必须保留旧证书。
	beforeFailure := manager.Status()
	if err := os.WriteFile(certPath, []byte("broken"), 0o644); err != nil {
		t.Fatalf("写入无效证书失败：%v", err)
	}
	if err := manager.Reload(context.Background()); err == nil {
		t.Fatal("并发握手期间无效证书重载应失败")
	}
	afterFailure := manager.Status()
	if afterFailure.Certificates[0].FingerprintSHA256 != beforeFailure.Certificates[0].FingerprintSHA256 {
		t.Fatal("并发重载失败后应保留旧证书")
	}
	// 恢复有效证书并再次成功重载，验证失败计数清零。
	_, _, recoveredCertPEM, recoveredKeyPEM := ca.issue(t, leafTemplate("login.example.com"))
	if err := os.WriteFile(certPath, recoveredCertPEM, 0o644); err != nil {
		t.Fatalf("恢复证书文件失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(keyPath, recoveredKeyPEM); err != nil {
		t.Fatalf("恢复私钥文件失败：%v", err)
	}
	if err := manager.Reload(context.Background()); err != nil {
		t.Fatalf("恢复后重载失败：%v", err)
	}
	close(stop)
	waitGroup.Wait()
	select {
	case err := <-errors:
		t.Fatalf("并发握手失败：%v", err)
	default:
	}
	if manager.Status().ReloadFailures != 0 {
		t.Fatal("成功重载后失败计数应清零")
	}
}

func TestReloadCheckedRejectsCandidate(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Root", true)
	_, _, certPEM, keyPEM := ca.issue(t, leafTemplate("login.example.com"))
	certPath := writePublic(t, dir, "server.crt", certPEM)
	keyPath := writeProtected(t, dir, "server.key", keyPEM)
	manager, err := New(Options{Source: Source{CertFiles: []string{certPath}, KeyFiles: []string{keyPath}}})
	if err != nil {
		t.Fatalf("加载证书失败：%v", err)
	}
	initial := manager.Status()

	// 写入另一张合法证书，但用 ReloadChecked 的校验函数拒绝它。
	_, _, newCertPEM, newKeyPEM := ca.issue(t, leafTemplate("login.example.com"))
	if err := os.WriteFile(certPath, newCertPEM, 0o644); err != nil {
		t.Fatalf("更新证书文件失败：%v", err)
	}
	if err := secrets.WriteProtectedFile(keyPath, newKeyPEM); err != nil {
		t.Fatalf("更新私钥文件失败：%v", err)
	}
	rejected := errors.New("候选证书未覆盖配置主机")
	if err := manager.ReloadChecked(context.Background(), func(Status) error { return rejected }); !errors.Is(err, rejected) {
		t.Fatalf("ReloadChecked 错误 = %v，期望候选校验错误", err)
	}
	afterReject := manager.Status()
	if afterReject.Certificates[0].FingerprintSHA256 != initial.Certificates[0].FingerprintSHA256 {
		t.Fatal("候选被拒绝后应保留旧证书")
	}
	if afterReject.ReloadFailures != 1 || !afterReject.LastReloadFailed {
		t.Fatalf("候选被拒绝后的状态 = %+v", afterReject)
	}
	// 去掉校验后再次重载成功，失败计数清零。
	if err := manager.Reload(context.Background()); err != nil {
		t.Fatalf("后续重载失败：%v", err)
	}
	if manager.Status().ReloadFailures != 0 {
		t.Fatal("成功重载后失败计数应清零")
	}
}

func TestExpiryStatus(t *testing.T) {
	dir := testutil.TempDir(t)
	ca := newTestAuthority(t, "Root", true)
	template := leafTemplate("login.example.com")
	template.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	_, _, certPEM, keyPEM := ca.issue(t, template)
	certPath := writePublic(t, dir, "server.crt", certPEM)
	keyPath := writeProtected(t, dir, "server.key", keyPEM)

	now := time.Now()
	manager, err := New(Options{
		Source:        Source{CertFiles: []string{certPath}, KeyFiles: []string{keyPath}},
		ExpiryWarning: 30 * 24 * time.Hour,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("加载证书失败：%v", err)
	}
	status := manager.Status()
	if !status.ExpiringSoon || status.Expired {
		t.Fatalf("10 天后到期应进入 30 天告警窗口：%+v", status)
	}
	now = now.Add(11 * 24 * time.Hour)
	status = manager.Status()
	if !status.Expired || !status.ExpiringSoon {
		t.Fatalf("超过有效期后应标记过期：%+v", status)
	}
}
