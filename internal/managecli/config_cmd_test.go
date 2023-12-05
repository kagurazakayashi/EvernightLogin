package managecli

// 本文件覆盖 `loginctl config` 的真实行为：脱敏展示、重载分类、预演不写、
// 原子写入与备份、秘密字段拒绝明文、秘密来源引用写入、差异分类与校验失败。

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
	"go.yaml.in/yaml/v3"
)

// TestConfigFieldKindsCoverAllFields 断言 CLI 写入类型表覆盖全部配置字段。
func TestConfigFieldKindsCoverAllFields(t *testing.T) {
	for _, field := range login.Fields() {
		kind, ok := configFieldKinds[field.Field]
		if !ok {
			t.Fatalf("字段 %s 缺少 CLI 写入类型", field.Field)
		}
		if field.Secret && kind != configKindSecret {
			t.Fatalf("秘密字段 %s 的类型是 %s", field.Field, kind)
		}
		if !field.Secret && kind == configKindSecret {
			t.Fatalf("非秘密字段 %s 被标记为 secret", field.Field)
		}
	}
}

// TestConfigShowClassifiesAndRedacts 验证 show 的重载分类与秘密脱敏。
func TestConfigShowClassifiesAndRedacts(t *testing.T) {
	stdout, stderr, exit := runCLI(t, "config", "show", "--json")
	if exit != ExitOK {
		t.Fatalf("config show 退出码 = %d，stderr=%s", exit, stderr)
	}
	envelope := decodeEnvelope(t, stdout)
	data := envelope["data"].(map[string]any)
	if data["valid"] != true {
		t.Fatalf("show 应报告有效配置: %v", data)
	}
	hot, _ := data["hot_reloadable"].([]any)
	if len(hot) == 0 {
		t.Fatal("应至少有一个可热更新字段")
	}
	restart, _ := data["restart_required"].([]any)
	if len(restart) == 0 {
		t.Fatal("应至少有一个需重启字段")
	}
	fields, _ := data["fields"].([]any)
	if len(fields) != len(login.Fields()) {
		t.Fatalf("字段数 = %d，期望 %d", len(fields), len(login.Fields()))
	}
	foundSecret := false
	for _, raw := range fields {
		item := raw.(map[string]any)
		if item["field"] == "secrets.master_key" {
			foundSecret = true
			if item["value"] != "[UNSET]" && item["value"] != "[REDACTED]" {
				t.Fatalf("秘密字段未脱敏: %v", item["value"])
			}
			if item["secret"] != true {
				t.Fatal("秘密字段标记丢失")
			}
		}
	}
	if !foundSecret {
		t.Fatal("未找到秘密字段")
	}
}

// TestConfigGetUnknownFieldReturnsUsage 验证未知字段的稳定退出码与错误码。
func TestConfigGetUnknownFieldReturnsUsage(t *testing.T) {
	stdout, _, exit := runCLI(t, "config", "get", "no.such_field", "--json")
	if exit != ExitUsage {
		t.Fatalf("未知字段退出码 = %d，期望 %d", exit, ExitUsage)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "CONFIG_FIELD_UNKNOWN" {
		t.Fatalf("错误码 = %s", code)
	}
}

// TestConfigValidateRejectsInvalidYAML 验证无效配置以退出码 1 拒绝。
func TestConfigValidateRejectsInvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("unknown_section:\n  key: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, exit := runCLI(t, "config", "validate", "--config", path, "--json")
	if exit != ExitError {
		t.Fatalf("无效配置退出码 = %d，期望 %d", exit, ExitError)
	}
	envelope := decodeEnvelope(t, stdout)
	if code := envelopeErrorCode(t, envelope); code != "CONFIG_INVALID" {
		t.Fatalf("错误码 = %s", code)
	}
	if _, ok := envelope["error"].(map[string]any)["details"]; !ok {
		t.Fatal("无效配置应返回结构化错误明细")
	}
}

// TestConfigSetDryRunDoesNotWrite 验证预演不创建/不修改文件。
func TestConfigSetDryRunDoesNotWrite(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "login.yaml")
	original := []byte("logging:\n  level: info\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := runCLI(t, "config", "set", "logging.level", "debug",
		"--file", path, "--dry-run", "--json")
	if exit != ExitOK {
		t.Fatalf("预演退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["written"] != false || data["dry_run"] != true {
		t.Fatalf("预演结果 = %v", data)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatalf("预演修改了配置文件: %s", current)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("预演不应创建备份文件")
	}
}

// TestConfigSetWritesAtomicWithBackup 验证真实写入、备份与有效配置可重新加载。
func TestConfigSetWritesAtomicWithBackup(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "login.yaml")
	if err := os.WriteFile(path, []byte("logging:\n  level: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := runCLI(t, "config", "set", "logging.level", "debug",
		"--file", path, "--json")
	if exit != ExitOK {
		t.Fatalf("写入退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["written"] != true || data["needs_restart"] != false {
		t.Fatalf("写入结果 = %v", data)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "level: debug") {
		t.Fatalf("写入内容缺失: %s", content)
	}
	backup := data["backup"].(string)
	if backup == "" {
		t.Fatal("缺少备份路径")
	}
	backupContent, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("备份文件不可读: %v", err)
	}
	if !strings.Contains(string(backupContent), "level: info") {
		t.Fatalf("备份内容不是原文件: %s", backupContent)
	}
	// 写入后的文件必须能通过既有加载器校验。
	if _, _, exit := runCLI(t, "config", "validate", "--config", path); exit != ExitOK {
		t.Fatalf("写入后配置无法通过校验，退出码 %d", exit)
	}
	// YAML 仍为两空格缩进且保留原有结构。
	if !strings.Contains(string(content), "logging:\n  level: debug") {
		t.Fatalf("YAML 排版异常: %s", content)
	}
}

// TestConfigSetRefusesSecretPlaintext 验证秘密值不能通过明文参数写入。
func TestConfigSetRefusesSecretPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login.yaml")
	if err := os.WriteFile(path, []byte("logging:\n  level: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := runCLI(t, "config", "set", "secrets.master_key",
		"deadbeef", "--file", path, "--json")
	if exit != ExitUsage {
		t.Fatalf("秘密字段退出码 = %d，stderr=%s", exit, stderr)
	}
	if code := envelopeErrorCode(t, decodeEnvelope(t, stdout)); code != "CONFIG_FIELD_SECRET" {
		t.Fatalf("错误码 = %s", code)
	}
	content, _ := os.ReadFile(path)
	if strings.Contains(string(content), "deadbeef") {
		t.Fatal("秘密明文进入了配置文件")
	}
}

// TestConfigSetSecretWritesSourceReference 验证 set-secret 只写 env:/file: 引用。
func TestConfigSetSecretWritesSourceReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login.yaml")
	if err := os.WriteFile(path, []byte("logging:\n  level: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := runCLI(t, "config", "set-secret", "secrets.master_key",
		"--source", "env:LOGIN_TEST_MASTER_KEY", "--file", path, "--json")
	if exit != ExitOK {
		t.Fatalf("set-secret 退出码 = %d，stderr=%s", exit, stderr)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		t.Fatalf("写入结果不是合法 YAML: %v", err)
	}
	if !strings.Contains(string(content), "env: LOGIN_TEST_MASTER_KEY") {
		t.Fatalf("缺少环境变量来源引用: %s", content)
	}
	if strings.Contains(string(content), "deadbeef") {
		t.Fatal("写入结果包含明文秘密")
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["new_value"] != "[env:LOGIN_TEST_MASTER_KEY]" {
		t.Fatalf("输出投影 = %v", data["new_value"])
	}
}

// TestConfigDiffClassifiesChanges 验证差异按重载分类拆分。
func TestConfigDiffClassifiesChanges(t *testing.T) {
	directory := t.TempDir()
	oldPath := filepath.Join(directory, "old.yaml")
	newPath := filepath.Join(directory, "new.yaml")
	if err := os.WriteFile(oldPath,
		[]byte("logging:\n  level: info\ndatabase:\n  wal: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath,
		[]byte("logging:\n  level: debug\ndatabase:\n  wal: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, exit := runCLI(t, "config", "diff", "--old", oldPath,
		"--new", newPath, "--json")
	if exit != ExitOK {
		t.Fatalf("diff 退出码 = %d，stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["changed"] != true {
		t.Fatalf("应检测到差异: %v", data)
	}
	hot, _ := data["hot_reloadable"].([]any)
	restart, _ := data["restart_required"].([]any)
	if len(hot) != 1 || hot[0] != "logging.level" {
		t.Fatalf("可热更新差异 = %v", hot)
	}
	if len(restart) != 1 || restart[0] != "database.wal" {
		t.Fatalf("需重启差异 = %v", restart)
	}
}

// TestConfigSetExpectedVersionConflict 验证 CLI 可选版本冲突检查与写入后版本输出。
func TestConfigSetExpectedVersionConflict(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "login.yaml")
	original := "logging:\n  level: info\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, exit := runCLI(t, "config", "set", "logging.level", "debug",
		"--file", path, "--expected-version", strings.Repeat("0", 64))
	if exit == ExitOK {
		t.Fatal("旧版本号写入必须失败")
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != original {
		t.Fatalf("版本冲突不得修改文件: %s err=%v", content, err)
	}
	digest := sha256.Sum256(content)
	version := hex.EncodeToString(digest[:])
	stdout, stderr, exit := runCLI(t, "config", "set", "logging.level", "debug",
		"--file", path, "--expected-version", version, "--json")
	if exit != ExitOK {
		t.Fatalf("正确版本写入失败: exit=%d stderr=%s", exit, stderr)
	}
	data := decodeEnvelope(t, stdout)["data"].(map[string]any)
	if data["written"] != true || data["version"] == "" {
		t.Fatalf("写入结果缺少新版本: %v", data)
	}
	updated, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(updated), "level: debug") {
		t.Fatalf("写入后内容异常: %s err=%v", updated, err)
	}
}
