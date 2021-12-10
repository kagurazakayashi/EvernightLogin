package managecli

// 本文件覆盖 `loginctl diag` 的真实诊断行为：健康/就绪、数据库与迁移、证书
// 有效期与私钥匹配、邮件明确不可用，以及不可验证状态不被当作通过。

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// diagChecks 把 diag JSON 输出转换为 name→check 映射。
func diagChecks(t *testing.T, output string) map[string]map[string]any {
	t.Helper()
	envelope := decodeEnvelope(t, output)
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		// 失败时 diag 仍应输出结构化 data。
		failure, _ := envelope["error"].(map[string]any)
		t.Fatalf("diag 输出缺少 data: %v", failure)
	}
	checks := make(map[string]map[string]any)
	rawChecks, _ := data["checks"].([]any)
	for _, raw := range rawChecks {
		item := raw.(map[string]any)
		name, _ := item["name"].(string)
		checks[name] = item
	}
	return checks
}

// TestDiagDatabaseAndReady 验证已迁移数据库的数据库检查通过、就绪因维护状态
// 未验证而不通过（不假定正常）。
func TestDiagDatabaseAndReady(t *testing.T) {
	databasePath, _ := newTestDatabase(t)
	configPath := writeConfigFile(t, t.TempDir(), databasePath)
	stdout, stderr, exit := runCLI(t, "diag", "database", "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("diag database 退出码 = %d，stderr=%s", exit, stderr)
	}
	checks := diagChecks(t, stdout)
	for _, name := range []string{"database", "database.integrity", "migration"} {
		if checks[name]["status"] != "ok" {
			t.Fatalf("检查 %s 状态 = %v", name, checks[name])
		}
	}
	// ready 在未提供维护状态目录/密钥时必须是 unverified 且退出码 1。
	stdout, _, exit = runCLI(t, "diag", "ready", "--config", configPath, "--json")
	if exit != ExitError {
		t.Fatalf("diag ready 退出码 = %d，期望 %d", exit, ExitError)
	}
	checks = diagChecks(t, stdout)
	if checks["maintenance"]["status"] != "unverified" {
		t.Fatalf("维护状态 = %v，期望 unverified", checks["maintenance"])
	}
	if checks["maintenance"]["code"] != "MAINTENANCE_STATE_UNVERIFIED" {
		t.Fatalf("维护状态错误码 = %v", checks["maintenance"]["code"])
	}
}

// TestDiagReadyWithInitializedMaintenance 验证已初始化且 normal 的维护状态使 ready 通过。
func TestDiagReadyWithInitializedMaintenance(t *testing.T) {
	databasePath, _ := newTestDatabase(t)
	directory := t.TempDir()
	configPath := writeConfigFile(t, directory, databasePath)
	_, keyringPath := newProtectedKeyringFile(t)
	stateDir := filepath.Join(t.TempDir(), "restore-state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := secrets.NewFileProvider(keyringPath)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := maintenance.New(maintenance.Options{StateDir: stateDir,
		DatabasePath: databasePath, Keyring: provider,
		Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("构造维护控制器: %v", err)
	}
	if err := controller.Initialize(context.Background(), maintenance.InitializeRequest{
		Operator: maintenance.LocalOperator(), Reason: "测试初始化"}); err != nil {
		t.Fatalf("初始化维护状态: %v", err)
	}
	stdout, stderr, exit := runCLI(t, "diag", "ready", "--config", configPath,
		"--state-dir", stateDir, "--keyring-file", keyringPath, "--json")
	if exit != ExitOK {
		t.Fatalf("diag ready 退出码 = %d，stderr=%s", exit, stderr)
	}
	checks := diagChecks(t, stdout)
	if checks["maintenance"]["status"] != "ok" {
		t.Fatalf("维护状态 = %v", checks["maintenance"])
	}
}

// TestDiagMailReportsUnavailable 验证邮件诊断明确返回不可用而不是伪成功。
func TestDiagMailReportsUnavailable(t *testing.T) {
	stdout, _, exit := runCLI(t, "diag", "mail", "--json")
	if exit != ExitError {
		t.Fatalf("diag mail 退出码 = %d，期望 %d", exit, ExitError)
	}
	checks := diagChecks(t, stdout)
	if checks["mail"]["status"] != "unavailable" {
		t.Fatalf("邮件状态 = %v", checks["mail"])
	}
	if checks["mail"]["code"] != "MAIL_DIAGNOSTICS_UNAVAILABLE" {
		t.Fatalf("邮件错误码 = %v", checks["mail"]["code"])
	}
}

// TestDiagDatabaseMissingDoesNotCreate 验证缺失数据库被拒绝且不会创建文件。
func TestDiagDatabaseMissingDoesNotCreate(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.db")
	configPath := writeConfigFile(t, t.TempDir(), missing)
	stdout, _, exit := runCLI(t, "diag", "database", "--config", configPath, "--json")
	if exit != ExitError {
		t.Fatalf("缺失数据库退出码 = %d，期望 %d", exit, ExitError)
	}
	checks := diagChecks(t, stdout)
	if checks["database"]["status"] != "unavailable" {
		t.Fatalf("数据库状态 = %v", checks["database"])
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("诊断命令创建了数据库文件")
	}
}

// TestDiagCertificateValidAndMismatchedKey 验证证书有效期与私钥匹配检查，
// 并确认输出不含私钥材料。
func TestDiagCertificateValidAndMismatchedKey(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := writeSelfSignedCertificate(t, directory, "server",
		testNow.Add(-time.Hour), testNow.Add(90*24*time.Hour))
	configPath := writeConfigFile(t, directory, filepath.Join(directory, "unused.db"))
	appendYAML(t, configPath, "server:\n  tls_cert_files: ["+quoteYAML(certPath)+
		"]\n  tls_key_files: ["+quoteYAML(keyPath)+"]\n")
	stdout, stderr, exit := runCLI(t, "diag", "certificate", "--config", configPath, "--json")
	if exit != ExitOK {
		t.Fatalf("证书诊断退出码 = %d，stderr=%s", exit, stderr)
	}
	checks := diagChecks(t, stdout)
	if checks["certificate"]["status"] != "ok" {
		t.Fatalf("证书状态 = %v", checks["certificate"])
	}
	if strings.Contains(stdout, "PRIVATE KEY") {
		t.Fatal("证书诊断输出泄露了私钥")
	}
	// 用另一把私钥替换后应报告不可用（私钥不匹配）。
	_, otherKey := writeSelfSignedCertificate(t, t.TempDir(), "other",
		testNow.Add(-time.Hour), testNow.Add(30*24*time.Hour))
	otherConfig := writeConfigFile(t, directory, filepath.Join(directory, "unused2.db"))
	appendYAML(t, otherConfig, "server:\n  tls_cert_files: ["+quoteYAML(certPath)+
		"]\n  tls_key_files: ["+quoteYAML(otherKey)+"]\n")
	stdout, _, exit = runCLI(t, "diag", "certificate", "--config", otherConfig, "--json")
	if exit != ExitError {
		t.Fatalf("不匹配私钥退出码 = %d，期望 %d", exit, ExitError)
	}
	checks = diagChecks(t, stdout)
	if checks["certificate"]["code"] != "CERT_KEY_MISMATCH" {
		t.Fatalf("证书错误码 = %v", checks["certificate"])
	}
}

// TestDiagCertificateExpired 验证过期证书报告 CERT_EXPIRED。
func TestDiagCertificateExpired(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := writeSelfSignedCertificate(t, directory, "expired",
		testNow.Add(-48*time.Hour), testNow.Add(-24*time.Hour))
	configPath := writeConfigFile(t, directory, filepath.Join(directory, "unused.db"))
	appendYAML(t, configPath, "server:\n  tls_cert_files: ["+quoteYAML(certPath)+
		"]\n  tls_key_files: ["+quoteYAML(keyPath)+"]\n")
	stdout, _, exit := runCLI(t, "diag", "certificate", "--config", configPath, "--json")
	if exit != ExitError {
		t.Fatalf("过期证书退出码 = %d，期望 %d", exit, ExitError)
	}
	if code := diagChecks(t, stdout)["certificate"]["code"]; code != "CERT_EXPIRED" {
		t.Fatalf("证书错误码 = %v", code)
	}
}

// quoteYAML 用 JSON 字符串形式安全嵌入路径（YAML 双引号转义与 JSON 兼容）。
func quoteYAML(value string) string {
	escaped := strings.ReplaceAll(value, "\\", "\\\\")
	return "\"" + escaped + "\""
}

// appendYAML 在配置文件后追加 YAML 片段（用于补充 TLS 段）。
func appendYAML(t *testing.T, path, fragment string) {
	t.Helper()
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(existing, []byte(fragment)...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeSelfSignedCertificate 生成自签名证书与 PKCS#8 私钥 PEM，返回两者路径。
func writeSelfSignedCertificate(t *testing.T, directory, prefix string,
	notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成私钥: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: prefix + ".example.test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{prefix + ".example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("签发测试证书: %v", err)
	}
	certPath := filepath.Join(directory, prefix+".crt")
	keyPath := filepath.Join(directory, prefix+".key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
