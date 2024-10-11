package setupconsole

// 步骤 293 的定向测试：脱敏导出、加密敏感包往返、占位符合并、导入预览。
// 全部使用临时合成配置与临时主密钥环，不接触真实数据。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// ws4ValidConfigTemplate 读取仓库内已验证的部署配置样例；测试环境缺少样例时
// 回退到最小内联配置（仅用于桩环境）。
func ws4ValidConfigTemplate(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "docs", "deployment", "samples", "login.server.example.yaml"),
		filepath.Join("docs", "deployment", "samples", "login.server.example.yaml"),
		// 隔离/桩环境下包目录不在仓库内时使用仓库绝对样例路径。
		filepath.Join("P:/go/src/github.com/kagurazakayashi/EvernightLogin", "docs", "deployment", "samples", "login.server.example.yaml"),
	}
	for _, candidate := range candidates {
		if raw, err := os.ReadFile(candidate); err == nil && len(raw) > 0 {
			return string(raw)
		}
	}
	return "server:\n  listen_addr: \"127.0.0.1:8080\"\n"
}

// ws4ConfigWithSecrets 在有效样例基础上补充秘密来源与固定数据库路径，返回可被
// 正式加载器接受的配置文本。
func ws4ConfigWithSecrets(t *testing.T, databasePath string) string {
	t.Helper()
	// 正式加载器会读取秘密来源；测试用受控环境变量提供合成主密钥材料（不是真实密钥）。
	t.Setenv("WS4_TEST_MASTER_KEY", "ws4-test-synthetic-master-key-material")
	base := ws4ValidConfigTemplate(t)
	base = strings.ReplaceAll(base, "/srv/evernight-login/data/login.db", filepath.ToSlash(databasePath))
	if !strings.Contains(base, "\nsecrets:") {
		base += "\nsecrets:\n  master_key:\n    env: WS4_TEST_MASTER_KEY\n"
	}
	return base
}

func writeConfigioFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("创建目录失败：%v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入临时配置失败：%v", err)
	}
}

func newTestKeyringFile(t *testing.T, dir, name string) string {
	t.Helper()
	ring, err := secrets.GenerateKeyring("test-key-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("生成测试密钥环失败：%v", err)
	}
	document, err := ring.Document()
	if err != nil {
		t.Fatalf("序列化测试密钥环失败：%v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("写入测试密钥环失败：%v", err)
	}
	return path
}

func TestMaskConfigYAMLRedactsSecretSources(t *testing.T) {
	configText := ws4ConfigWithSecrets(t, "P:/go/tmp/ws4/data/login.db")
	masked, fields, err := MaskConfigYAML([]byte(configText))
	if err != nil {
		t.Fatalf("脱敏失败：%v", err)
	}
	text := string(masked)
	if strings.Contains(text, "WS4_TEST_MASTER_KEY") {
		t.Fatal("脱敏导出不应包含秘密来源名称")
	}
	if !strings.Contains(text, maskedPlaceholder) {
		t.Fatal("脱敏导出必须包含占位符")
	}
	if !strings.Contains(text, "listen_addr") {
		t.Fatal("非秘密字段应保留")
	}
	if len(fields) == 0 {
		t.Fatalf("应记录脱敏字段：%+v", fields)
	}
}

func TestExportMaskedConfigWritesNewFileOnly(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "login.yaml")
	writeConfigioFile(t, source, ws4ConfigWithSecrets(t, filepath.ToSlash(filepath.Join(dir, "login.db"))))
	target := filepath.Join(dir, "exported.yaml")
	result, err := ExportMaskedConfig(ConfigExportOptions{ConfigPath: source, OutputPath: target})
	if err != nil {
		t.Fatalf("脱敏导出失败：%v", err)
	}
	if result.SizeBytes <= 0 || result.SHA256 == "" {
		t.Fatalf("导出结果缺少大小/摘要：%+v", result)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("脱敏导出文件不存在：%v", err)
	}
	if _, err := ExportMaskedConfig(ConfigExportOptions{ConfigPath: source, OutputPath: target}); err == nil {
		t.Fatal("导出目标已存在时必须拒绝覆盖")
	}
	if _, err := ExportMaskedConfig(ConfigExportOptions{ConfigPath: source, OutputPath: "relative.yaml"}); err == nil {
		t.Fatal("相对导出目标必须被拒绝")
	}
}

func TestEncryptedConfigPackageRoundTripAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	databasePath := filepath.ToSlash(filepath.Join(dir, "login.db"))
	configText := ws4ConfigWithSecrets(t, databasePath)
	report := ValidateConfigText([]byte(configText))
	if !report.Valid {
		t.Fatalf("测试配置应通过校验：%s %+v", report.Summary, report.Issues)
	}
	source := filepath.Join(dir, "login.yaml")
	writeConfigioFile(t, source, configText)
	keyFile := newTestKeyringFile(t, dir, "master.key")
	packagePath := filepath.Join(dir, "sensitive.lncfg")
	summary, err := ExportEncryptedConfigPackage(context.Background(), ConfigExportOptions{
		ConfigPath: source, OutputPath: packagePath, MasterKeyFile: keyFile, Operator: "ws4-test",
	})
	if err != nil {
		t.Fatalf("导出加密配置包失败：%v", err)
	}
	if summary.ConfigSHA256 == "" || summary.PackageSHA256 == "" || summary.FormatVersion != configPackageVersion {
		t.Fatalf("加密包元数据不完整：%+v", summary)
	}
	decrypted, err := ReadEncryptedConfigPackage(context.Background(), packagePath, keyFile)
	if err != nil {
		t.Fatalf("解密配置包失败：%v", err)
	}
	if string(decrypted.Raw) != configText {
		t.Fatalf("往返后配置不一致：%q", string(decrypted.Raw))
	}
	if !decrypted.Report.Valid {
		t.Fatal("解密后的配置应通过校验")
	}

	raw, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatalf("读取配置包失败：%v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0xff
	tamperedPath := filepath.Join(dir, "tampered.lncfg")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("写入篡改包失败：%v", err)
	}
	if _, err := ReadEncryptedConfigPackage(context.Background(), tamperedPath, keyFile); err == nil {
		t.Fatal("篡改后的配置包必须认证失败")
	}

	otherKey := newTestKeyringFile(t, dir, "other.key")
	if _, err := ReadEncryptedConfigPackage(context.Background(), packagePath, otherKey); err == nil {
		t.Fatal("错误主密钥环必须解密失败")
	}
}

func TestMergeMaskedConfigPreservesCurrentSecrets(t *testing.T) {
	dir := t.TempDir()
	current := ws4ConfigWithSecrets(t, filepath.ToSlash(filepath.Join(dir, "data", "login.db")))
	// 让导入文件在非秘密字段上有变化：修改监听端口。
	maskedSource := strings.ReplaceAll(current, `"127.0.0.1:8080"`, `"127.0.0.1:9090"`)
	masked, _, err := MaskConfigYAML([]byte(maskedSource))
	if err != nil {
		t.Fatalf("脱敏失败：%v", err)
	}
	merged, remaining, err := MergeMaskedConfig([]byte(current), masked)
	if err != nil {
		t.Fatalf("合并失败：%v", err)
	}
	text := string(merged)
	if !strings.Contains(text, "env: WS4_TEST_MASTER_KEY") {
		t.Fatal("脱敏占位不应覆盖现有秘密来源")
	}
	if !strings.Contains(text, "127.0.0.1:9090") {
		t.Fatal("导入的非秘密字段应覆盖当前值")
	}
	if len(remaining) == 0 {
		t.Fatal("应报告仍需保留/补全的占位字段")
	}
}

func TestPreviewConfigImportDetectsDatabaseSwitch(t *testing.T) {
	dir := t.TempDir()
	currentPath := filepath.Join(dir, "login.yaml")
	writeConfigioFile(t, currentPath, ws4ConfigWithSecrets(t, filepath.ToSlash(filepath.Join(dir, "data", "login.db"))))
	importedYAML := ws4ConfigWithSecrets(t, filepath.ToSlash(filepath.Join(dir, "other", "login.db")))
	importPath := filepath.Join(dir, "imported.yaml")
	writeConfigioFile(t, importPath, importedYAML)

	preview, err := PreviewConfigImport(context.Background(), ConfigImportRequest{
		ImportPath: importPath, CurrentConfigPath: currentPath,
	})
	if err != nil {
		t.Fatalf("导入预览失败：%v", err)
	}
	if preview.SourceKind != "masked-yaml" {
		t.Fatalf("来源类型错误：%s", preview.SourceKind)
	}
	if preview.DatabasePathChange == "" {
		t.Fatal("应检测到数据库定位变化")
	}
	if !strings.Contains(preview.DatabasePathChange, "other") {
		t.Fatalf("数据库变化描述不准确：%s", preview.DatabasePathChange)
	}
	if preview.RequiredConfirm != "IMPORT-CONFIG" {
		t.Fatalf("确认串错误：%s", preview.RequiredConfirm)
	}
	if len(preview.Diff) == 0 {
		t.Fatal("应产生行级差异")
	}
	if !preview.CanApply {
		t.Fatalf("合法导入应可应用，阻塞：%v %+v", preview.Blocking, preview.ProposedReport.Issues)
	}
	if _, err := ApplyConfigImport(context.Background(), nil, ConfigImportRequest{}); err == nil {
		t.Fatal("未注入保存接口时必须拒绝应用")
	}
}

func TestConfigIOScreenRendersAndValidatesInputs(t *testing.T) {
	screen := NewConfigIOScreen()
	canvas := NewCanvas(80, 30)
	session := SessionView{}
	screen.Render(context.Background(), canvas, session)
	ctx := context.Background()
	// 无配置/导入路径时预览必须拒绝而不是 panic。
	if closeScreen, err := screen.HandleKey(ctx, Key{Kind: KeyRune, Rune: 'p'}, session); closeScreen || err != nil {
		t.Fatalf("p 键不应关闭画面：%v %v", closeScreen, err)
	}
	if screen.errText == "" {
		t.Fatal("缺少路径时预览应显示错误")
	}
	if closeScreen, err := screen.HandleKey(ctx, Key{Kind: KeyEsc}, session); !closeScreen || err != nil {
		t.Fatalf("Esc 应关闭画面：%v %v", closeScreen, err)
	}
}

func TestConfigIOScreenMaskedExportViaModel(t *testing.T) {
	dir := t.TempDir()
	configText := ws4ConfigWithSecrets(t, filepath.ToSlash(filepath.Join(dir, "login.db")))
	configPath := filepath.Join(dir, "login.yaml")
	writeConfigioFile(t, configPath, configText)
	screen := NewConfigIOScreen()
	screen.configPath = configPath
	screen.outputDir = dir
	session := SessionView{Detection: Detection{ConfigPath: configPath}}
	screen.exportMasked(session)
	if screen.errText != "" {
		t.Fatalf("画面脱敏导出失败：%s", screen.errText)
	}
	if screen.exportPath == "" {
		t.Fatal("脱敏导出应记录输出路径")
	}
	if _, err := os.Stat(screen.exportPath); err != nil {
		t.Fatalf("脱敏导出文件不存在：%v", err)
	}
}
