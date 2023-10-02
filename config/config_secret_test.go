package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"go.yaml.in/yaml/v3"
)

const testSecretValue = "top-secret-value-9f3c"

func writeSecretFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(testutil.TempDir(t), "master.key")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("写入测试秘密文件失败：%v", err)
	}
	return path
}

func yamlSecretFile(path string) string {
	return "secrets:\n  master_key:\n    file: \"" + filepath.ToSlash(path) + "\"\n"
}

func TestSecretRedaction(t *testing.T) {
	secret := NewSecretString(testSecretValue)
	if !secret.IsSet() {
		t.Fatal("NewSecretString 应标记为已设置")
	}
	if secret.Len() != len(testSecretValue) {
		t.Errorf("Len() = %d，期望 %d", secret.Len(), len(testSecretValue))
	}

	outputs := []string{
		secret.String(),
		secret.GoString(),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%s", secret),
		fmt.Sprintf("%q", secret),
		fmt.Sprintf("%x", secret),
		fmt.Sprintf("%#v", secret),
	}
	text, err := secret.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText 失败：%v", err)
	}
	outputs = append(outputs, string(text))
	jsonBytes, err := json.Marshal(map[string]Secret{"master": secret})
	if err != nil {
		t.Fatalf("JSON 序列化失败：%v", err)
	}
	outputs = append(outputs, string(jsonBytes))
	yamlBytes, err := yaml.Marshal(map[string]Secret{"master": secret})
	if err != nil {
		t.Fatalf("YAML 序列化失败：%v", err)
	}
	outputs = append(outputs, string(yamlBytes))

	for _, output := range outputs {
		if strings.Contains(output, testSecretValue) {
			t.Fatalf("秘密内容出现在输出中：%q", output)
		}
	}
	if !strings.Contains(secret.String(), "[REDACTED]") {
		t.Errorf("String() 未使用脱敏标记：%q", secret.String())
	}

	var unset Secret
	if unset.IsSet() || unset.Len() != 0 || unset.Value() != nil {
		t.Error("Secret 零值应表示未设置")
	}
	if !strings.Contains(unset.String(), "[UNSET]") {
		t.Errorf("未设置秘密标记不正确：%q", unset.String())
	}
}

func TestSecretValueReturnsCopy(t *testing.T) {
	secret := NewSecretString(testSecretValue)
	first := secret.Value()
	if string(first) != testSecretValue {
		t.Fatalf("Value() = %q", first)
	}
	first[0] = 'X'
	second := secret.Value()
	if string(second) != testSecretValue {
		t.Fatalf("修改 Value() 副本影响了秘密内容：%q", second)
	}
}

func TestParseSecretSource(t *testing.T) {
	absoluteSecretPath := filepath.Join(testutil.TempDir(t), "master.key")
	valid := []struct {
		spec string
		kind SecretSourceKind
		name string
	}{
		{"env:LOGIN_MASTER_KEY", SecretSourceEnv, "LOGIN_MASTER_KEY"},
		{"file:" + absoluteSecretPath, SecretSourceFile, absoluteSecretPath},
	}
	for _, test := range valid {
		t.Run("有效 "+test.spec, func(t *testing.T) {
			source, err := ParseSecretSource(test.spec)
			if err != nil {
				t.Fatalf("ParseSecretSource(%q) 失败：%v", test.spec, err)
			}
			if source.Kind != test.kind || source.Name != test.name {
				t.Errorf("来源 = %+v", source)
			}
		})
	}

	invalid := []string{
		"",
		"LOGIN_MASTER_KEY",
		"env:",
		"env:9BAD",
		"env:BAD-NAME",
		"file:relative/key",
		"vault:secret",
	}
	for _, spec := range invalid {
		t.Run("无效 "+spec, func(t *testing.T) {
			if _, err := ParseSecretSource(spec); err == nil {
				t.Errorf("ParseSecretSource(%q) 应失败", spec)
			}
		})
	}
}

func TestSecretFromYAMLFileSource(t *testing.T) {
	path := writeSecretFile(t, testSecretValue+"\n", 0o600)
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(yamlSecretFile(path))})
	if !cfg.Secrets.MasterKey.IsSet() {
		t.Fatal("秘密文件来源应解析出秘密")
	}
	if got := string(cfg.Secrets.MasterKey.Value()); got != testSecretValue {
		t.Fatalf("秘密值 = %q，期望去掉行尾换行后的 %q", got, testSecretValue)
	}

	diagnostic := cfg.Diagnostic()
	if strings.Contains(diagnostic, testSecretValue) {
		t.Fatalf("脱敏诊断泄露秘密值：\n%s", diagnostic)
	}
	if strings.Contains(diagnostic, filepath.ToSlash(path)) {
		t.Fatalf("脱敏诊断泄露秘密文件路径：\n%s", diagnostic)
	}
}

func TestSecretFromYAMLEnvSource(t *testing.T) {
	yamlConfig := "secrets:\n  master_key:\n    env: TEST_MASTER_KEY\n"
	cfg := mustLoad(t, LoadOptions{
		YAML:      yamlBytes(yamlConfig),
		LookupEnv: envLookup(map[string]string{"TEST_MASTER_KEY": testSecretValue}),
	})
	if got := string(cfg.Secrets.MasterKey.Value()); got != testSecretValue {
		t.Fatalf("秘密值 = %q", got)
	}
	if strings.Contains(cfg.Diagnostic(), testSecretValue) {
		t.Fatal("脱敏诊断泄露秘密值")
	}
}

func TestSecretInlineYAMLRejected(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"标量秘密值", "secrets:\n  master_key: \"" + testSecretValue + "\"\n"},
		{"同时设置两种来源", "secrets:\n  master_key:\n    env: A\n    file: \"/tmp/x\"\n"},
		{"空来源映射", "secrets:\n  master_key: {}\n"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			errs := loadErrors(t, LoadOptions{YAML: yamlBytes(test.yaml)})
			if strings.Contains(errs.Error(), testSecretValue) {
				t.Fatalf("秘密错误泄露了内容：%v", errs)
			}
			if findConfigError(errs, ConfigErrorValue, "secrets.master_key") == nil &&
				findConfigError(errs, ConfigErrorConflict, "secrets.master_key") == nil &&
				findConfigError(errs, ConfigErrorSecretSource, "secrets.master_key") == nil {
				t.Fatalf("缺少秘密配置错误：%v", errs)
			}
		})
	}
}

func TestSecretEnvDirectOverridesYAMLSource(t *testing.T) {
	// YAML 指向不存在的文件，但环境变量直接提供值；环境变量优先级更高，不应读文件。
	missing := filepath.Join(testutil.TempDir(t), "missing.key")
	cfg := mustLoad(t, LoadOptions{
		YAML:      yamlBytes(yamlSecretFile(missing)),
		LookupEnv: envLookup(map[string]string{envSecretsMasterKey: testSecretValue}),
	})
	if got := string(cfg.Secrets.MasterKey.Value()); got != testSecretValue {
		t.Fatalf("环境变量秘密应覆盖 YAML 来源，实际 %q", got)
	}
}

func TestSecretOptionsOverrideEnv(t *testing.T) {
	cfg := mustLoad(t, LoadOptions{
		LookupEnv: envLookup(map[string]string{envSecretsMasterKey: "env-value"}),
		Overrides: &Overrides{Secrets: SecretsOverrides{MasterKey: Ptr(NewSecretString(testSecretValue))}},
	})
	if got := string(cfg.Secrets.MasterKey.Value()); got != testSecretValue {
		t.Fatalf("显式代码选项秘密应最高优先级，实际 %q", got)
	}
}

func TestSecretSourceErrors(t *testing.T) {
	t.Run("YAML 文件不存在", func(t *testing.T) {
		missing := filepath.Join(testutil.TempDir(t), "missing.key")
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlSecretFile(missing))})
		requireConfigError(t, errs, ConfigErrorSecretSource, "secrets.master_key")
	})

	t.Run("YAML 环境变量未设置", func(t *testing.T) {
		errs := loadErrors(t, LoadOptions{
			YAML:      yamlBytes("secrets:\n  master_key:\n    env: MISSING_MASTER_KEY\n"),
			LookupEnv: envLookup(map[string]string{}),
		})
		requireConfigError(t, errs, ConfigErrorSecretSource, "secrets.master_key")
	})

	t.Run("环境变量秘密为空", func(t *testing.T) {
		errs := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{envSecretsMasterKey: ""})})
		requireConfigError(t, errs, ConfigErrorValue, "secrets.master_key")
	})

	t.Run("环境变量秘密过大", func(t *testing.T) {
		errs := loadErrors(t, LoadOptions{LookupEnv: envLookup(map[string]string{
			envSecretsMasterKey: strings.Repeat("x", MaxSecretBytes+1),
		})})
		requireConfigError(t, errs, ConfigErrorRange, "secrets.master_key")
	})

	t.Run("秘密文件为空", func(t *testing.T) {
		path := writeSecretFile(t, "\r\n", 0o600)
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlSecretFile(path))})
		requireConfigError(t, errs, ConfigErrorSecretSource, "secrets.master_key")
	})

	t.Run("秘密文件过大", func(t *testing.T) {
		path := writeSecretFile(t, strings.Repeat("x", MaxSecretBytes+1), 0o600)
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlSecretFile(path))})
		requireConfigError(t, errs, ConfigErrorSecretSource, "secrets.master_key")
	})

	t.Run("秘密来源是目录", func(t *testing.T) {
		dir := testutil.TempDir(t)
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlSecretFile(dir))})
		requireConfigError(t, errs, ConfigErrorSecretSource, "secrets.master_key")
	})

	t.Run("非 Windows 平台拒绝过宽文件权限", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows 使用 ACL 而非 Unix 权限位，文件权限保护由步骤 08 验证")
		}
		path := writeSecretFile(t, testSecretValue, 0o644)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("修改文件权限失败：%v", err)
		}
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(yamlSecretFile(path))})
		requireConfigError(t, errs, ConfigErrorSecretSource, "secrets.master_key")
	})
}

func TestSecretOptionsInvalid(t *testing.T) {
	t.Run("显式选项空秘密", func(t *testing.T) {
		errs := loadErrors(t, LoadOptions{
			Overrides: &Overrides{Secrets: SecretsOverrides{MasterKey: Ptr(Secret{})}},
		})
		requireConfigError(t, errs, ConfigErrorValue, "secrets.master_key")
	})

	t.Run("显式选项秘密过大", func(t *testing.T) {
		errs := loadErrors(t, LoadOptions{
			Overrides: &Overrides{Secrets: SecretsOverrides{
				MasterKey: Ptr(NewSecretString(strings.Repeat("x", MaxSecretBytes+1))),
			}},
		})
		requireConfigError(t, errs, ConfigErrorRange, "secrets.master_key")
	})
}
