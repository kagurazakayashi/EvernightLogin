package mailer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

// TestLoadTrustedRoots 覆盖：只追加有效 PEM、无效文件/缺失路径启动失败。
func TestLoadTrustedRoots(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(valid, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mailer.LoadTrustedRoots([]string{valid}); err != nil {
		t.Fatalf("有效 PEM 应加载成功: %v", err)
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mailer.LoadTrustedRoots([]string{bad}); err == nil {
		t.Fatal("无效 PEM 应失败")
	}
	if _, err := mailer.LoadTrustedRoots([]string{filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("缺失信任根应失败")
	}
}

// selfSignedPEM 生成临时自签 CA PEM，仅用于测试信任根加载。
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mailer-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
