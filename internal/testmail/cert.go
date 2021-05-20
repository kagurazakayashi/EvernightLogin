package testmail

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
	"time"
)

// GenerateTestCertificate 生成一张仅用于测试的 ECDSA P-256 自签名证书。
//
// 证书用于 STARTTLS 测试：自签名意味着客户端必须显式信任该证书或跳过校验，
// 生产环境绝不能使用本函数。hosts 为证书要覆盖的主机名或 IP（例如 localhost、
// 127.0.0.1）；为空时默认使用 localhost、127.0.0.1 与 ::1。证书有效期 24 小时
// （允许 1 小时时钟偏差），不包含任何真实密钥或组织信息。
func GenerateTestCertificate(hosts ...string) (tls.Certificate, error) {
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          newSerialNumber(),
		Subject:               pkix.Name{CommonName: "testmail.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("testmail: 生成测试私钥失败: %w", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("testmail: 生成测试证书失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("testmail: 编码测试私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("testmail: 组装测试证书失败: %w", err)
	}
	return cert, nil
}

// newSerialNumber 生成 128 位正随机序列号。
func newSerialNumber() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		// crypto/rand 失败属于不可恢复的环境问题；测试基础设施直接 panic 比
		// 返回带可预测序列号的证书更安全。
		panic(fmt.Sprintf("testmail: 生成证书序列号失败: %v", err))
	}
	return n
}
