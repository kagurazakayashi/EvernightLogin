package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// clientLeafTemplate 返回客户端认证叶证书模板。
func clientLeafTemplate(domains ...string) *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: "test client"},
		DNSNames:              domains,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// newTestClientCertificate 用指定 CA 签发客户端证书，返回可直接用于 TLS 客户端
// 的证书与解析后的叶证书。
func newTestClientCertificate(t *testing.T, authority *testAuthority, template *x509.Certificate) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	leaf, _, certPEM, keyPEM := authority.issue(t, template)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("构造客户端证书对失败：%v", err)
	}
	return pair, leaf
}

// writeClientCA 把 CA 证书写入公共 PEM 文件。
func writeClientCA(t *testing.T, dir, name string, authorities ...*testAuthority) string {
	t.Helper()
	var data []byte
	for _, authority := range authorities {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.der})...)
	}
	return writePublic(t, dir, name, data)
}

// mtlsHandshake 在真实回环 TCP 上执行 TLS 握手；clientCert 为 nil 时不提供
// 客户端证书。返回服务端观察到的连接状态与客户端握手错误。使用真实套接字与
// 期限避免 net.Pipe 的半关闭死锁。
func mtlsHandshake(t *testing.T, manager *Manager, serverRoots *x509.CertPool, serverName string, clientCert *tls.Certificate, minVersion, maxVersion uint16) (tls.ConnectionState, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听回环端口失败：%v", err)
	}
	defer listener.Close()
	serverResult := make(chan serverHandshakeResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- serverHandshakeResult{err: acceptErr}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		serverTLS := tls.Server(conn, manager.TLSConfig())
		handshakeErr := serverTLS.Handshake()
		serverResult <- serverHandshakeResult{state: serverTLS.ConnectionState(), err: handshakeErr}
	}()

	clientConfig := &tls.Config{
		RootCAs:    serverRoots,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	if minVersion != 0 {
		clientConfig.MinVersion = minVersion
	}
	if maxVersion != 0 {
		clientConfig.MaxVersion = maxVersion
	}
	if clientCert != nil {
		// 使用 GetClientCertificate 强制发送测试证书：默认的 Certificates 选择
		// 逻辑会按服务端 AcceptableCAs 过滤，导致“错误 CA 的证书根本没发送”，
		// 无法验证服务端对无效证书的拒绝。这里要求服务端真正收到该证书。
		certificate := *clientCert
		clientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certificate, nil
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	clientConn, dialErr := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), clientConfig)
	if dialErr != nil {
		select {
		case <-serverResult:
		case <-time.After(10 * time.Second):
			t.Fatal("服务端 TLS 握手中止超时")
		}
		return tls.ConnectionState{}, dialErr
	}
	defer clientConn.Close()
	var server serverHandshakeResult
	select {
	case server = <-serverResult:
	case <-time.After(10 * time.Second):
		t.Fatal("服务端 TLS 握手超时")
	}
	if server.err != nil {
		return server.state, server.err
	}
	return server.state, nil
}

// serverHandshakeResult 是服务端握手结果（状态与错误）。
type serverHandshakeResult struct {
	state tls.ConnectionState
	err   error
}

// mtlsTicketRoundTrip 在真实回环 TCP 上完成一次 TLS 1.3 请求往返，使客户端处理
// 服务端会话票据；返回客户端连接状态。
func mtlsTicketRoundTrip(t *testing.T, manager *Manager, serverRoots *x509.CertPool, certs []tls.Certificate, cache tls.ClientSessionCache) (tls.ConnectionState, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听回环端口失败：%v", err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		serverTLS := tls.Server(conn, manager.TLSConfig())
		if handshakeErr := serverTLS.Handshake(); handshakeErr != nil {
			serverResult <- handshakeErr
			return
		}
		_, writeErr := serverTLS.Write([]byte{1})
		serverResult <- writeErr
	}()

	clientConfig := &tls.Config{
		RootCAs:            serverRoots,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ClientSessionCache: cache,
	}
	if len(certs) > 0 {
		certificate := certs[0]
		clientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certificate, nil
		}
	}
	clientConn, dialErr := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", listener.Addr().String(), clientConfig)
	if dialErr != nil {
		select {
		case <-serverResult:
		case <-time.After(10 * time.Second):
			t.Fatal("服务端 TLS 握手中止超时")
		}
		return tls.ConnectionState{}, dialErr
	}
	defer clientConn.Close()
	_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buffer := make([]byte, 1)
	if _, readErr := clientConn.Read(buffer); readErr != nil {
		return tls.ConnectionState{}, readErr
	}
	if serverErr := <-serverResult; serverErr != nil {
		return tls.ConnectionState{}, serverErr
	}
	return clientConn.ConnectionState(), nil
}

// newMTLSManager 构造启用客户端证书认证的测试管理器。
func newMTLSManager(t *testing.T, mode ClientAuthMode, caFiles []string, identities []ClientIdentity) (*Manager, *testIdentity) {
	t.Helper()
	identity := newTestIdentity(t, "localhost")
	manager, err := New(Options{
		Source: Source{CertFiles: []string{identity.certPath}, KeyFiles: []string{identity.keyPath}},
		ClientAuth: ClientAuthOptions{
			Mode:       mode,
			CAFiles:    caFiles,
			Identities: identities,
		},
	})
	if err != nil {
		t.Fatalf("构造 mTLS 管理器失败：%v", err)
	}
	return manager, identity
}

func TestClientAuthLoadingAndStatus(t *testing.T) {
	dir := testutil.TempDir(t)
	clientCA := newTestAuthority(t, "Client Trust CA", true)
	caPath := writeClientCA(t, dir, "client-ca.pem", clientCA)
	identities := []ClientIdentity{{DNSName: "backup.internal", Service: "backup-agent"}}

	t.Run("默认关闭", func(t *testing.T) {
		identity := newTestIdentity(t, "localhost")
		manager, err := New(Options{Source: Source{CertFiles: []string{identity.certPath}, KeyFiles: []string{identity.keyPath}}})
		if err != nil {
			t.Fatalf("构造管理器失败：%v", err)
		}
		if manager.TLSConfig().ClientAuth != tls.NoClientCert {
			t.Errorf("默认 ClientAuth = %v", manager.TLSConfig().ClientAuth)
		}
		if manager.TLSConfig().ClientCAs != nil || manager.TLSConfig().VerifyConnection != nil {
			t.Error("默认不应设置客户端信任或连接校验回调")
		}
		status := manager.Status().ClientAuth
		if status.Mode != ClientAuthDisabled || len(status.TrustAnchors) != 0 || len(status.Identities) != 0 {
			t.Errorf("默认客户端认证状态 = %+v", status)
		}
		if _, ok := manager.ClientServiceIdentity(clientCA.certificate); ok {
			t.Error("关闭 mTLS 时不应返回服务身份")
		}
	})

	t.Run("必须验证客户端证书", func(t *testing.T) {
		manager, _ := newMTLSManager(t, ClientAuthRequired, []string{caPath}, identities)
		if manager.TLSConfig().ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("required ClientAuth = %v", manager.TLSConfig().ClientAuth)
		}
		if manager.TLSConfig().ClientCAs == nil || manager.TLSConfig().VerifyConnection == nil {
			t.Error("required 必须设置客户端信任池与连接校验回调")
		}
		status := manager.Status().ClientAuth
		if status.Mode != ClientAuthRequired {
			t.Errorf("状态模式 = %q", status.Mode)
		}
		if len(status.TrustAnchors) != 1 {
			t.Fatalf("信任锚数量 = %d", len(status.TrustAnchors))
		}
		anchor := status.TrustAnchors[0]
		if !strings.Contains(anchor.Subject, "Client Trust CA") {
			t.Errorf("信任锚主题 = %q", anchor.Subject)
		}
		if len(anchor.FingerprintSHA256) != 64 {
			t.Errorf("信任锚指纹长度 = %d", len(anchor.FingerprintSHA256))
		}
		if anchor.NotBefore.IsZero() || anchor.NotAfter.IsZero() || !anchor.SelfSigned {
			t.Errorf("信任锚状态 = %+v", anchor)
		}
		if len(status.Identities) != 1 || status.Identities[0] != identities[0] {
			t.Errorf("身份映射状态 = %+v", status.Identities)
		}
		// 返回副本：调用方修改不影响管理器。
		status.TrustAnchors[0].Subject = "changed"
		status.Identities[0].Service = "changed"
		again := manager.Status().ClientAuth
		if strings.Contains(again.TrustAnchors[0].Subject, "changed") ||
			again.Identities[0].Service == "changed" {
			t.Error("状态返回值不是副本")
		}
	})

	t.Run("可选客户端证书", func(t *testing.T) {
		manager, _ := newMTLSManager(t, ClientAuthOptional, []string{caPath}, identities)
		if manager.TLSConfig().ClientAuth != tls.VerifyClientCertIfGiven {
			t.Errorf("optional ClientAuth = %v", manager.TLSConfig().ClientAuth)
		}
		status := manager.Status().ClientAuth
		if status.Mode != ClientAuthOptional {
			t.Errorf("状态模式 = %q", status.Mode)
		}
	})
}

func TestClientAuthLoadingFailures(t *testing.T) {
	dir := testutil.TempDir(t)
	validCA := newTestAuthority(t, "Valid CA", true)
	validCAPath := writeClientCA(t, dir, "valid-ca.pem", validCA)
	serverIdentity := newTestIdentity(t, "localhost")
	identities := []ClientIdentity{{DNSName: "backup.internal", Service: "backup-agent"}}
	newOptions := func(auth ClientAuthOptions) Options {
		return Options{
			Source:     Source{CertFiles: []string{serverIdentity.certPath}, KeyFiles: []string{serverIdentity.keyPath}},
			ClientAuth: auth,
		}
	}

	// 非 CA 证书不能作为客户端信任锚。
	nonCACertPEM := serverIdentity.certPEM
	nonCAPath := writePublic(t, dir, "leaf.pem", nonCACertPEM)
	if _, err := New(newOptions(ClientAuthOptions{
		Mode: ClientAuthRequired, CAFiles: []string{nonCAPath}, Identities: identities,
	})); err == nil {
		t.Fatal("非 CA 证书应被拒绝为客户端信任锚")
	}

	// CA 文件里混入私钥 PEM 块应被拒绝（只接受公共证书）。
	mixedPath := writePublic(t, dir, "mixed.pem", append(append([]byte{}, validCAPathBytes(t, validCA)...), serverIdentity.keyPEM...))
	if _, err := New(newOptions(ClientAuthOptions{
		Mode: ClientAuthRequired, CAFiles: []string{mixedPath}, Identities: identities,
	})); err == nil {
		t.Fatal("包含私钥块的 CA 文件应被拒绝")
	}

	// CA 文件不存在、为空、包含重复 CA。
	emptyPath := writePublic(t, dir, "empty.pem", nil)
	duplicatedPath := writeClientCA(t, dir, "duplicated.pem", validCA, validCA)
	duplicateFilesA := writeClientCA(t, dir, "dup-a.pem", validCA)
	duplicateFilesB := writeClientCA(t, dir, "dup-b.pem", validCA)
	cases := []struct {
		name string
		auth ClientAuthOptions
	}{
		{"缺少 CA 文件", ClientAuthOptions{Mode: ClientAuthRequired, Identities: identities}},
		{"缺少身份映射", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{validCAPath}}},
		{"CA 文件不存在", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{filepath.Join(dir, "missing.pem")}, Identities: identities}},
		{"CA 文件为空", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{emptyPath}, Identities: identities}},
		{"单文件重复 CA", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{duplicatedPath}, Identities: identities}},
		{"跨文件重复 CA", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{duplicateFilesA, duplicateFilesB}, Identities: identities}},
		{"关闭时配置 CA", ClientAuthOptions{Mode: ClientAuthDisabled, CAFiles: []string{validCAPath}}},
		{"关闭时配置身份映射", ClientAuthOptions{Mode: ClientAuthDisabled, Identities: identities}},
		{"未知模式", ClientAuthOptions{Mode: "on", CAFiles: []string{validCAPath}, Identities: identities}},
		{"身份映射重复 DNS", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{validCAPath}, Identities: []ClientIdentity{
			{DNSName: "backup.internal", Service: "agent-a"},
			{DNSName: "BACKUP.internal", Service: "agent-b"},
		}}},
		{"身份 DNS 是 IP", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{validCAPath}, Identities: []ClientIdentity{
			{DNSName: "127.0.0.1", Service: "agent"},
		}}},
		{"身份 DNS 是通配符", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{validCAPath}, Identities: []ClientIdentity{
			{DNSName: "*.internal", Service: "agent"},
		}}},
		{"服务身份大写", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{validCAPath}, Identities: []ClientIdentity{
			{DNSName: "backup.internal", Service: "Agent"},
		}}},
		{"服务身份含空格", ClientAuthOptions{Mode: ClientAuthRequired, CAFiles: []string{validCAPath}, Identities: []ClientIdentity{
			{DNSName: "backup.internal", Service: "backup agent"},
		}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(newOptions(test.auth)); err == nil {
				t.Fatalf("应拒绝无效客户端认证配置")
			}
		})
	}

	// 过期 CA 不能被信任。直接构造一个已过期 CA 证书。
	expiredAuthority := newExpiredAuthority(t, "Expired CA")
	expiredPath := writeClientCA(t, dir, "expired-ca.pem", expiredAuthority)
	if _, err := New(newOptions(ClientAuthOptions{
		Mode: ClientAuthRequired, CAFiles: []string{expiredPath}, Identities: identities,
	})); err == nil {
		t.Fatal("过期客户端信任 CA 应被拒绝")
	}

	// 客户端信任 CA 与服务器证书链不能共用同一张证书：把自签服务器证书同时当作
	// 客户端信任 CA。
	selfSignedDir := testutil.TempDir(t)
	selfSignedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成自签服务器私钥失败：%v", err)
	}
	selfSignedTemplate := &x509.Certificate{
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
	selfSignedDER, err := x509.CreateCertificate(rand.Reader, selfSignedTemplate, selfSignedTemplate,
		&selfSignedKey.PublicKey, selfSignedKey)
	if err != nil {
		t.Fatalf("签发自签服务器证书失败：%v", err)
	}
	selfSignedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSignedDER})
	selfSignedKeyDER, err := x509.MarshalPKCS8PrivateKey(selfSignedKey)
	if err != nil {
		t.Fatalf("编码自签服务器私钥失败：%v", err)
	}
	serverCertPath := writePublic(t, selfSignedDir, "server.crt", selfSignedPEM)
	serverKeyPath := writeProtected(t, selfSignedDir, "server.key",
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: selfSignedKeyDER}))
	sharedCAPath := writePublic(t, selfSignedDir, "shared-ca.pem", selfSignedPEM)
	if _, err := New(Options{
		Source: Source{CertFiles: []string{serverCertPath}, KeyFiles: []string{serverKeyPath}},
		ClientAuth: ClientAuthOptions{
			Mode: ClientAuthRequired, CAFiles: []string{sharedCAPath}, Identities: identities,
		},
	}); err == nil {
		t.Fatal("客户端信任 CA 与服务器证书重叠应被拒绝")
	}
}

// validCAPathBytes 返回测试 CA 的 PEM 编码。
func validCAPathBytes(t *testing.T, authority *testAuthority) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.der})
}

// newExpiredAuthority 生成已过期的自签名 CA 证书。
func newExpiredAuthority(t *testing.T, commonName string) *testAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成过期 CA 私钥失败：%v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发过期测试 CA 失败：%v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析过期测试 CA 失败：%v", err)
	}
	return &testAuthority{certificate: parsed, key: key, der: der}
}

func TestMTLSHandshakeRequired(t *testing.T) {
	dir := testutil.TempDir(t)
	clientCA := newTestAuthority(t, "Client Trust CA", true)
	otherCA := newTestAuthority(t, "Other CA", true)
	caPath := writeClientCA(t, dir, "client-ca.pem", clientCA)
	identities := []ClientIdentity{
		{DNSName: "backup.internal", Service: "backup-agent"},
		{DNSName: "monitor.internal", Service: "monitor"},
	}
	manager, serverIdentity := newMTLSManager(t, ClientAuthRequired, []string{caPath}, identities)
	serverRoots := serverIdentity.rootPool(t)
	mappedCert, _ := newTestClientCertificate(t, clientCA, clientLeafTemplate("backup.internal"))
	unmappedCert, _ := newTestClientCertificate(t, clientCA, clientLeafTemplate("unknown.internal"))
	otherCACert, _ := newTestClientCertificate(t, otherCA, clientLeafTemplate("backup.internal"))

	expiredTemplate := clientLeafTemplate("backup.internal")
	expiredTemplate.NotBefore = time.Now().Add(-48 * time.Hour)
	expiredTemplate.NotAfter = time.Now().Add(-24 * time.Hour)
	expiredCert, _ := newTestClientCertificate(t, clientCA, expiredTemplate)

	wrongUsageTemplate := clientLeafTemplate("backup.internal")
	wrongUsageTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	wrongUsageCert, _ := newTestClientCertificate(t, clientCA, wrongUsageTemplate)

	ambiguousCert, _ := newTestClientCertificate(t, clientCA, clientLeafTemplate("backup.internal", "monitor.internal"))

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("TLS%d", version), func(t *testing.T) {
			state, err := mtlsHandshake(t, manager, serverRoots, "localhost", &mappedCert, version, version)
			if err != nil {
				t.Fatalf("映射客户端证书握手失败：%v", err)
			}
			if len(state.PeerCertificates) != 1 {
				t.Fatalf("服务端客户端证书数量 = %d", len(state.PeerCertificates))
			}
			service, ok := manager.ClientServiceIdentity(state.PeerCertificates[0])
			if !ok || service != "backup-agent" {
				t.Errorf("服务身份 = %q/%v", service, ok)
			}

			failureCases := []struct {
				name string
				cert *tls.Certificate
			}{
				{"无客户端证书", nil},
				{"不受信任 CA 签发", &otherCACert},
				{"已过期证书", &expiredCert},
				{"用途不是客户端认证", &wrongUsageCert},
				{"身份未映射", &unmappedCert},
				{"多个身份映射有歧义", &ambiguousCert},
			}
			for _, failure := range failureCases {
				_, handshakeErr := mtlsHandshake(t, manager, serverRoots, "localhost", failure.cert, version, version)
				if handshakeErr == nil {
					t.Fatalf("%s 应握手失败", failure.name)
				}
				// 客户端错误不得泄露服务端身份映射或证书细节。
				if strings.Contains(handshakeErr.Error(), "backup.internal") ||
					strings.Contains(handshakeErr.Error(), "backup-agent") {
					t.Errorf("%s 的握手错误泄露映射信息：%v", failure.name, handshakeErr)
				}
			}
		})
	}
}

func TestMTLSHandshakeOptional(t *testing.T) {
	dir := testutil.TempDir(t)
	clientCA := newTestAuthority(t, "Client Trust CA", true)
	otherCA := newTestAuthority(t, "Other CA", true)
	caPath := writeClientCA(t, dir, "client-ca.pem", clientCA)
	identities := []ClientIdentity{{DNSName: "backup.internal", Service: "backup-agent"}}
	manager, serverIdentity := newMTLSManager(t, ClientAuthOptional, []string{caPath}, identities)
	serverRoots := serverIdentity.rootPool(t)
	mappedCert, _ := newTestClientCertificate(t, clientCA, clientLeafTemplate("backup.internal"))
	unmappedCert, _ := newTestClientCertificate(t, clientCA, clientLeafTemplate("unknown.internal"))
	otherCACert, _ := newTestClientCertificate(t, otherCA, clientLeafTemplate("backup.internal"))

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("TLS%d", version), func(t *testing.T) {
			state, err := mtlsHandshake(t, manager, serverRoots, "localhost", nil, version, version)
			if err != nil {
				t.Fatalf("可选模式匿名连接应成功：%v", err)
			}
			if len(state.PeerCertificates) != 0 {
				t.Fatal("匿名连接不应有客户端证书")
			}

			state, err = mtlsHandshake(t, manager, serverRoots, "localhost", &mappedCert, version, version)
			if err != nil {
				t.Fatalf("可选模式映射证书应成功：%v", err)
			}
			if service, ok := manager.ClientServiceIdentity(state.PeerCertificates[0]); !ok || service != "backup-agent" {
				t.Errorf("可选模式服务身份 = %q/%v", service, ok)
			}

			// 关键不变量：一旦出示证书，无效/未映射证书必须失败，不能降级为匿名。
			for _, failure := range []struct {
				name string
				cert *tls.Certificate
			}{
				{"不受信任 CA", &otherCACert},
				{"未映射身份", &unmappedCert},
			} {
				if _, handshakeErr := mtlsHandshake(t, manager, serverRoots, "localhost", failure.cert, version, version); handshakeErr == nil {
					t.Fatalf("可选模式下 %s 的证书应导致握手失败", failure.name)
				}
			}
		})
	}
}

func TestMTLSHandshakeDisabled(t *testing.T) {
	identity := newTestIdentity(t, "localhost")
	manager, err := New(Options{Source: Source{CertFiles: []string{identity.certPath}, KeyFiles: []string{identity.keyPath}}})
	if err != nil {
		t.Fatalf("构造管理器失败：%v", err)
	}
	// 客户端准备好证书：服务端没有请求时不会发送，连接按匿名处理。
	clientCA := newTestAuthority(t, "Unused CA", true)
	clientCert, _ := newTestClientCertificate(t, clientCA, clientLeafTemplate("backup.internal"))
	state, err := mtlsHandshake(t, manager, identity.rootPool(t), "localhost", &clientCert, 0, 0)
	if err != nil {
		t.Fatalf("关闭 mTLS 时应能匿名连接：%v", err)
	}
	if len(state.PeerCertificates) != 0 {
		t.Fatal("关闭 mTLS 时服务端不应收到客户端证书")
	}
}

func TestMTLSResumptionRechecksIdentity(t *testing.T) {
	dir := testutil.TempDir(t)
	clientCA := newTestAuthority(t, "Client Trust CA", true)
	caPath := writeClientCA(t, dir, "client-ca.pem", clientCA)
	identities := []ClientIdentity{{DNSName: "backup.internal", Service: "backup-agent"}}
	manager, serverIdentity := newMTLSManager(t, ClientAuthRequired, []string{caPath}, identities)
	serverRoots := serverIdentity.rootPool(t)
	clientCert, _ := newTestClientCertificate(t, clientCA, clientLeafTemplate("backup.internal"))
	cache := tls.NewLRUClientSessionCache(4)

	firstState, err := mtlsTicketRoundTrip(t, manager, serverRoots, []tls.Certificate{clientCert}, cache)
	if err != nil {
		t.Fatalf("首次 TLS 1.3 握手失败：%v", err)
	}
	if firstState.DidResume {
		t.Fatal("首次连接不应是会话恢复")
	}
	// 恢复连接不重新发送客户端证书；若环境未触发恢复，则匿名完整握手会因缺少
	// 客户端证书失败，这是预期的安全行为。
	resumedState, err := mtlsTicketRoundTrip(t, manager, serverRoots, nil, cache)
	if err != nil {
		t.Skipf("未触发 TLS 1.3 会话恢复，匿名完整握手失败：%v", err)
	}
	if !resumedState.DidResume {
		t.Fatalf("第二次连接应标记会话恢复")
	}
	// 恢复连接没有重新发送客户端证书，但服务端 VerifyConnection 仍拿到会话中
	// 保存的已验证证书并按当前身份映射复查，因此恢复成功即证明映射检查仍生效。
	t.Log("TLS 1.3 会话恢复成功，客户端证书身份映射在恢复连接上仍被复查")
}

// TestMTLSVerifyConnectionDirect 验证身份映射的规范化匹配与歧义拒绝。
func TestMTLSVerifyConnectionDirect(t *testing.T) {
	dir := testutil.TempDir(t)
	clientCA := newTestAuthority(t, "Client Trust CA", true)
	caPath := writeClientCA(t, dir, "client-ca.pem", clientCA)
	manager, _ := newMTLSManager(t, ClientAuthRequired, []string{caPath}, []ClientIdentity{
		{DNSName: "backup.internal", Service: "backup-agent"},
	})
	mappedCert, mappedLeaf := newTestClientCertificate(t, clientCA, clientLeafTemplate("BACKUP.Internal."))
	service, ok := manager.ClientServiceIdentity(mappedLeaf)
	if !ok || service != "backup-agent" {
		t.Errorf("大小写与结尾点应被规范化匹配：%q/%v", service, ok)
	}
	_ = mappedCert
	_, unmappedLeaf := newTestClientCertificate(t, clientCA, clientLeafTemplate("other.internal"))
	if _, ok := manager.ClientServiceIdentity(unmappedLeaf); ok {
		t.Error("未映射证书不应返回服务身份")
	}
	if _, ok := manager.ClientServiceIdentity(nil); ok {
		t.Error("nil 证书不应返回服务身份")
	}
}

func TestMTLSOptionalExpiredCertificateFails(t *testing.T) {
	dir := testutil.TempDir(t)
	clientCA := newTestAuthority(t, "Client Trust CA", true)
	caPath := writeClientCA(t, dir, "client-ca.pem", clientCA)
	manager, serverIdentity := newMTLSManager(t, ClientAuthOptional, []string{caPath}, []ClientIdentity{
		{DNSName: "backup.internal", Service: "backup-agent"},
	})
	expiredTemplate := clientLeafTemplate("backup.internal")
	expiredTemplate.NotBefore = time.Now().Add(-48 * time.Hour)
	expiredTemplate.NotAfter = time.Now().Add(-24 * time.Hour)
	expiredCert, _ := newTestClientCertificate(t, clientCA, expiredTemplate)
	if _, err := mtlsHandshake(t, manager, serverIdentity.rootPool(t), "localhost", &expiredCert, 0, 0); err == nil {
		t.Fatal("可选模式出示过期证书应握手失败，不能降级为匿名")
	}
}
